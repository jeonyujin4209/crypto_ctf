use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use common::{ClientCommand, ServerCommand};

use anyhow::Result;
use messages::{ProtocolMessage, RecommitteeMessage};
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_prime::nt_funcs::is_prime;
use openssl::bn::BigNum;
use rand::prelude::*;
use tracing::{debug, error, info, trace};

mod cli;
mod connection;
mod messages;

use connection::{Connection, Message};

#[tokio::main]
async fn main() -> Result<()> {
    cli::main().await
}

struct InjectSecret<'a> {
    user: &'a str,
    secret: &'a str,
    channel: &'a str,
    forced_user: Option<&'a str>,
}

struct ProtocolParameters {
    committee_size: usize,
    threshold: usize,
    panic_threshold: usize,
}

const PARAMS: ProtocolParameters = ProtocolParameters {
    committee_size: 10,
    threshold: 5,
    panic_threshold: 35,
};

fn get_random_safe_prime(bits: i32) -> BigUint {
    let mut p = BigNum::new().expect("failed to allocate BigNum for prime");
    p.generate_prime(bits, true, None, None)
        .expect("failed to generate safe prime");
    BigUint::from_bytes_be(&p.to_vec())
}

async fn inject_secret(
    connection: &mut Connection,
    InjectSecret {
        user: myself,
        secret,
        channel,
        forced_user,
    }: InjectSecret<'_>,
) -> Result<()> {
    let secret = BigUint::from_bytes_le(secret.as_bytes());

    let mut rng = StdRng::from_entropy();

    let ident: String = (0..8)
        .map(|_| {
            let choices = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            choices.chars().choose(&mut rng).unwrap()
        })
        .collect();

    let g = BigUint::from(2u8);
    let q = loop {
        // fingers crossed
        let p = get_random_safe_prime(512 + 1);
        let q = (&p - BigUint::from(1u32)) >> 1;
        let p_mod_8 = &p % BigUint::from(8u32);
        if g.modpow(&q, &p) != BigUint::from(1u32) {
            continue;
        }
        if p_mod_8 != BigUint::from(1u32) && p_mod_8 != BigUint::from(7u32) {
            continue;
        }
        if !is_prime(&q, None).probably() {
            continue;
        }
        if !is_prime(&p, None).probably() {
            continue;
        }
        break q;
    };
    assert!(
        secret < q,
        "secret ({} bits) does not fit within q ({} bits)",
        secret.bits(),
        q.bits()
    );

    let (shares, commitments) = generate_shares_and_commits(secret, &mut rng, &q, &g);

    connection
        .send(ClientCommand::ListUsers(channel.to_owned()))
        .await?;
    let users: Vec<_> = match connection.recv_cmd().await? {
        ServerCommand::UserList(users) => users.into_iter().filter(|u| u != myself).collect(),
        cmd => panic!("Invalid command from server: {cmd:?}"),
    };

    if users.len() < PARAMS.committee_size {
        panic!("Insufficient number of users to form a committee");
    }

    let users: Users = {
        let mut users = users;
        users.shuffle(&mut rng);
        match forced_user {
            None => {}
            Some(u) => {
                if !users.iter().any(|x| x == u) {
                    panic!("Could not find user {u}; only existing users are {users:?}");
                }
                while !users.iter().take(PARAMS.committee_size).any(|x| x == u) {
                    users.shuffle(&mut rng);
                }
            }
        }
        users.truncate(PARAMS.committee_size);
        Users::new(users)
    };
    debug!(?users, "Users selected");

    connection
        .send_to_channel(
            myself,
            channel,
            &ProtocolMessage::Commitments {
                ident: ident.clone(),
                q_g: (q.clone(), g.clone()),
                commitments: commitments.clone(),
                users: users.clone(),
            },
        )
        .await?;

    for (i, (user, share)) in users.into_iter().zip(shares.into_iter()).enumerate() {
        let key = i + 1;
        debug_assert!(is_share_valid(&q, &g, &commitments, key, &share));
        connection
            .send_dm_to(
                myself,
                &user,
                &ProtocolMessage::Share {
                    ident: ident.clone(),
                    key,
                    value: share.clone(),
                },
            )
            .await?;
    }

    Ok(())
}

fn generate_shares_and_commits(
    secret: BigUint,
    rng: &mut StdRng,
    q: &BigUint,
    g: &BigUint,
) -> (Vec<BigUint>, Vec<BigUint>) {
    let q_by_two = q.clone() / 2u32;

    // Coefficients in [q/2, q) to avoid weaker polynomials
    let polynomial: Vec<BigUint> = std::iter::once(secret.clone())
        .chain((1..PARAMS.threshold).map(|_| rng.gen_biguint_range(&q_by_two, q)))
        .collect();

    let shares: Vec<BigUint> = (1..=PARAMS.committee_size)
        .map(|x| {
            polynomial
                .iter()
                .enumerate()
                .map(|(i, a)| BigUint::from(x).modpow(&i.into(), q) * a)
                .sum::<BigUint>()
                % q
        })
        .collect();

    let commitments: Vec<BigUint> = polynomial
        .iter()
        .map(|a| g.modpow(a, &(q * 2u8 + 1u8)))
        .collect();

    {
        let values: Vec<_> = std::iter::once(None)
            .chain(shares.iter().cloned().map(Some))
            .collect();
        for (k, v) in values.iter().enumerate() {
            if let Some(v) = v.as_ref() {
                assert!(is_share_valid(q, g, &commitments, k, v));
            }
        }
        let recovered = recover_from_shares(q, &values);
        assert_eq!(recovered, secret, "Created an unrecoverable secret?!");
    }

    (shares, commitments)
}

struct GeneralUser<'a> {
    user: &'a str,
    channel: &'a str,
}

struct RequestRelease<'a> {
    user: &'a str,
    ident: &'a str,
    channel: &'a str,
}

async fn request_release(
    connection: &mut Connection,
    RequestRelease {
        user: myself,
        ident,
        channel,
    }: RequestRelease<'_>,
) -> Result<()> {
    info!(ident, "Requesting share release");
    connection
        .send_to_channel(
            myself,
            channel,
            &ProtocolMessage::Release {
                ident: ident.to_string(),
            },
        )
        .await?;
    let general_user_loop = tokio::time::timeout(
        Duration::from_secs(5),
        general_user(
            connection,
            GeneralUser {
                user: myself,
                channel,
            },
        ),
    )
    .await;
    match general_user_loop {
        Ok(result) => result,
        Err(_) => {
            error!(ident, "Timeout: Failed to receive shares fast enough");
            anyhow::bail!("Timeout waiting for share release")
        }
    }
}

async fn general_user(
    connection: &mut Connection,
    GeneralUser {
        user: myself,
        channel,
    }: GeneralUser<'_>,
) -> Result<()> {
    let mut db: HashMap<String, ShareInfo> = Default::default();

    let mut rng = StdRng::from_entropy();

    let mut last_tested = Instant::now();

    loop {
        if let Some(msg) = connection.next_message() {
            macro_rules! expect_from {
                ($expected:expr) => {
                    if msg.channel != $expected {
                        trace!(
                            expected = $expected,
                            got = msg.channel,
                            "Ignoring message from wrong channel"
                        );
                        continue;
                    }
                };
            }

            if !(msg.channel == channel || msg.channel == "@") {
                trace!(
                    expected_channel = channel,
                    got = msg.channel,
                    "Ignoring message from wrong channel"
                );
                continue;
            }
            let Ok(protocol_message): Result<ProtocolMessage, _> = msg.message.parse() else {
                continue;
            };
            match protocol_message {
                ProtocolMessage::Share { ident, key, value } => {
                    expect_from!("@");
                    let Some(info) = db.get_mut(&ident) else {
                        continue;
                    };
                    if msg.from != info.initiator {
                        continue;
                    }
                    if !is_share_valid(&info.q_g.0, &info.q_g.1, &info.commitments, key, &value) {
                        error!("Got an invalid share?!");
                        continue;
                    }
                    info.share = Some((key, value));
                }
                ProtocolMessage::Release { ident } => {
                    expect_from!(channel);
                    let Some(info) = db.get(&ident) else {
                        continue;
                    };
                    if info.initiator != msg.from {
                        continue;
                    }
                    if let Some((key, value)) = &info.share {
                        connection
                            .send_dm_to(
                                myself,
                                &msg.from,
                                &ProtocolMessage::ReleasedShare {
                                    ident: ident.clone(),
                                    key: *key,
                                    value: value.clone(),
                                    q: info.q_g.0.clone(),
                                    g: info.q_g.1.clone(),
                                },
                            )
                            .await?;
                    }
                    db.remove(&ident);
                }
                ProtocolMessage::ReleasedShare {
                    ident,
                    key,
                    value,
                    q,
                    g,
                } => {
                    expect_from!("@");
                    let info = db.entry(ident.clone()).or_insert_with(|| ShareInfo {
                        users: Default::default(),
                        initiator: myself.to_string(),
                        q_g: (q.clone(), g.clone()),
                        commitments: vec![],
                        share: Default::default(),
                        released_share: Default::default(),
                        recommitteeing: None,
                    });
                    if info.q_g.0 != q || info.q_g.1 != g {
                        error!("Mismatched q/g for released share!");
                        continue;
                    }
                    if key == 0 || key > PARAMS.committee_size {
                        error!("Invalid key!");
                        continue;
                    }
                    info.released_share.insert(key, value);
                    if info.released_share.len() >= PARAMS.threshold {
                        let mut values = vec![None; PARAMS.committee_size + 1];
                        for (k, v) in &info.released_share {
                            values[*k] = Some(v.clone());
                        }
                        let secret = recover_from_shares(&q, &values).to_bytes_le();
                        let secret_str = String::from_utf8_lossy(&secret);
                        info!(ident, ?secret, %secret_str, "Recovered secret");
                    }
                }
                ProtocolMessage::Commitments {
                    ident,
                    q_g,
                    commitments,
                    users,
                } => {
                    expect_from!(channel);
                    if users.contains(myself) {
                        db.insert(
                            ident,
                            ShareInfo {
                                users,
                                q_g,
                                initiator: msg.from,
                                commitments,
                                share: Default::default(),
                                released_share: Default::default(),
                                recommitteeing: None,
                            },
                        );
                    }
                }
                ProtocolMessage::Recommittee {
                    ident,
                    nonce,
                    recomm_msg,
                } => {
                    recommittee(
                        connection, &mut rng, channel, myself, &mut db, msg, ident, nonce,
                        recomm_msg,
                    )
                    .await?;
                }
            }
        } else if db
            .values()
            .filter_map(|s| s.recommitteeing.as_ref())
            .any(|recomm| recomm.latest_message.elapsed().as_secs() > 3)
        {
            let (ident, share_info) = db
                .iter()
                .find(|(_, s)| match s.recommitteeing.as_ref() {
                    None => false,
                    Some(recomm) => recomm.latest_message.elapsed().as_secs() > 3,
                })
                .unwrap();
            let recomm = share_info.recommitteeing.as_ref().unwrap();
            let rs = recomm
                .revealed_shares
                .iter()
                .cloned()
                .filter(|&s| {
                    let commit = share_info.q_g.1.modpow(&s.into(), &share_info.q_g.0);
                    recomm.commits.contains(&Some(commit))
                })
                .collect::<Vec<_>>();
            if recomm.new_users.is_empty() {
                if rs.len() >= PARAMS.threshold {
                    let active_users = connection.active_users(channel).await?;
                    let r: usize = rs.into_iter().fold(0, |a, x| a ^ x).try_into().unwrap();
                    let user = active_users[r % active_users.len()].clone();
                    connection
                        .send_to_channel_and_enqueue_self(
                            myself,
                            channel,
                            &ProtocolMessage::Recommittee {
                                ident: ident.into(),
                                nonce: recomm.nonce,
                                recomm_msg: RecommitteeMessage::Begin {
                                    user,
                                    initiator: share_info.initiator.clone(),
                                    q: share_info.q_g.0.clone(),
                                    g: share_info.q_g.1.clone(),
                                    old_users: share_info.users.clone(),
                                },
                            },
                        )
                        .await?;
                } else if !share_info.users.is_empty() {
                    connection
                        .send_to_channel_and_enqueue_self(
                            myself,
                            channel,
                            &ProtocolMessage::Recommittee {
                                ident: ident.into(),
                                nonce: recomm.nonce,
                                recomm_msg: RecommitteeMessage::Abort {
                                    blame: "ProtocolBreach".into(),
                                },
                            },
                        )
                        .await?;
                }
            } else if recomm.blinders.t.is_some() {
                let ident = ident.clone();
                let mut old_share_info = db.remove(&ident).unwrap();
                let recomm = old_share_info.recommitteeing.take().unwrap();
                let share = recomm.blinders.into_share(&old_share_info.q_g);
                db.insert(
                    ident,
                    ShareInfo {
                        users: recomm.new_users,
                        initiator: old_share_info.initiator,
                        q_g: old_share_info.q_g,
                        commitments: vec![],
                        share,
                        released_share: Default::default(),
                        recommitteeing: None,
                    },
                );
                debug!("Finished transitioning to new share_info")
            }
        } else if last_tested.elapsed().as_secs_f64() > 10.0 * PARAMS.committee_size as f64 {
            last_tested = Instant::now();
            let active_users = connection.active_users(channel).await?;
            for (share_id, share_info) in &db {
                if !share_info.users.all_active(&active_users)
                    && share_info.recommitteeing.is_none()
                {
                    let pm = ProtocolMessage::Recommittee {
                        ident: share_id.clone(),
                        nonce: rng.r#gen(),
                        recomm_msg: RecommitteeMessage::Propose,
                    };
                    connection
                        .send_to_channel_and_enqueue_self(myself, channel, &pm)
                        .await?;
                }
            }
        } else if rng.gen_bool(0.0001) {
            info!("Decided to quit");
            return Ok(());
        }
        // Pull in more messages
        connection
            .try_block_to_refill_recv_buffer(Duration::from_millis(rng.gen_range(125..250)))
            .await?;
    }
}

#[allow(clippy::too_many_arguments)]
async fn recommittee(
    connection: &mut Connection,
    rng: &mut StdRng,
    channel: &str,
    myself: &str,
    db: &mut HashMap<String, ShareInfo>,
    msg: Message,
    ident: String,
    nonce: u32,
    recomm_msg: RecommitteeMessage,
) -> Result<()> {
    if let RecommitteeMessage::Abort { blame } = recomm_msg {
        let Some(share_info) = db.get_mut(&ident) else {
            debug!(blame, "Trying to abort a non-existent share");
            return Ok(());
        };
        let Some(recomm) = &share_info.recommitteeing else {
            debug!(blame, "Trying to abort a non-recommitteeing share");
            return Ok(());
        };
        if recomm.nonce != nonce {
            debug!(blame, "Trying to abort the wrong recommitteeing");
            return Ok(());
        }
        share_info.recommitteeing = None;
        debug!(from = msg.from, msg = msg.message, "Received Recomm Abort");
        return Ok(());
    }

    macro_rules! abort_recomm {
        () => {{
            tracing::debug!(
                msg.from,
                msg = msg.message,
                line = line!(),
                "Requesting an abort"
            );
            connection
                .send_to_channel_and_enqueue_self(
                    myself,
                    channel,
                    &ProtocolMessage::Recommittee {
                        ident,
                        nonce,
                        recomm_msg: RecommitteeMessage::Abort { blame: msg.from },
                    },
                )
                .await?;
            return Ok(());
        }};
    }

    let share_info = match db.get_mut(&ident) {
        None => match &recomm_msg {
            RecommitteeMessage::Begin {
                user,
                initiator,
                q,
                g,
                old_users,
            } if user == myself => {
                db.insert(
                    ident.clone(),
                    ShareInfo {
                        users: old_users.clone(),
                        initiator: initiator.clone(),
                        q_g: (q.clone(), g.clone()),
                        commitments: vec![],
                        share: Default::default(),
                        released_share: Default::default(),
                        recommitteeing: Some(RecommInfo {
                            latest_message: Instant::now(),
                            nonce,
                            proposed_share: 0,
                            commits: vec![],
                            revealed_shares: Default::default(),
                            new_users: Default::default(),
                            blinders: Blinders::new(BigUint::from(0u32), old_users.len()),
                            blinding_released: false,
                        }),
                    },
                );
                db.get_mut(&ident).unwrap()
            }
            _ => {
                // This is not relevant to me, going away
                return Ok(());
            }
        },
        Some(share_info) => share_info,
    };

    debug!(from = msg.from, msg = msg.message, "Received recomm msg");

    macro_rules! expect_from {
        ($expected:expr) => {
            if msg.channel != $expected {
                trace!(
                    expected = $expected,
                    got = msg.channel,
                    "Ignoring message from wrong channel"
                );
                return Ok(());
            }
        };
    }
    match recomm_msg {
        RecommitteeMessage::Propose
        | RecommitteeMessage::NewUserCommit { .. }
        | RecommitteeMessage::NewUserReveal { .. }
        | RecommitteeMessage::Abort { .. }
        | RecommitteeMessage::Begin { .. }
        | RecommitteeMessage::NewGenCommits { .. }
        | RecommitteeMessage::BlindedRelease { .. }
        | RecommitteeMessage::PublicRelease { .. } => {
            expect_from!(channel);
        }
        RecommitteeMessage::NewGenShares { .. } => {
            expect_from!("@");
        }
    }

    if let RecommitteeMessage::Propose = recomm_msg {
        if share_info.recommitteeing.is_some() {
            abort_recomm!()
        }
        let active_users = connection.active_users(channel).await?;
        if share_info.users.all_active(&active_users) {
            abort_recomm!()
        }
        let proposed_share: u64 = rng.r#gen();
        let commit = share_info
            .q_g
            .1
            .modpow(&proposed_share.into(), &share_info.q_g.0);
        let commits = vec![None; share_info.users.len()];
        share_info.recommitteeing = Some(RecommInfo {
            latest_message: Instant::now(),
            nonce,
            proposed_share,
            commits,
            revealed_shares: Default::default(),
            new_users: Default::default(),
            blinders: Blinders::new(
                rng.gen_biguint_range(&0u8.into(), &share_info.q_g.0),
                share_info.users.len(),
            ),
            blinding_released: false,
        });
        if share_info.share.is_some() {
            connection
                .send_to_channel_and_enqueue_self(
                    myself,
                    channel,
                    &ProtocolMessage::Recommittee {
                        ident: ident.clone(),
                        nonce,
                        recomm_msg: RecommitteeMessage::NewUserCommit {
                            commit: commit.clone(),
                        },
                    },
                )
                .await?;
        }
        return Ok(());
    }

    let Some(recomm) = &mut share_info.recommitteeing else {
        abort_recomm!()
    };

    if recomm.nonce != nonce {
        abort_recomm!()
    }

    recomm.latest_message = Instant::now();

    match recomm_msg {
        RecommitteeMessage::Propose | RecommitteeMessage::Abort { .. } => {
            unreachable!()
        }
        RecommitteeMessage::NewUserCommit { commit } => {
            let Some(idx) = (0..recomm.commits.len())
                .filter(|&i| recomm.commits[i].is_none())
                .find(|&i| share_info.users.user_is(i, |u| u == &msg.from))
            else {
                abort_recomm!()
            };
            recomm.commits[idx] = Some(commit);
            let active_users = connection.active_users(channel).await?;
            if recomm.commits.iter().enumerate().all(|(i, c)| {
                if share_info.users.user_is(i, |u| active_users.contains(u)) {
                    // If they are active, they should have committed
                    c.is_some()
                } else {
                    true
                }
            }) && share_info.share.is_some()
            {
                connection
                    .send_to_channel_and_enqueue_self(
                        myself,
                        channel,
                        &ProtocolMessage::Recommittee {
                            ident: ident.clone(),
                            nonce,
                            recomm_msg: RecommitteeMessage::NewUserReveal {
                                proposed_share: recomm.proposed_share,
                            },
                        },
                    )
                    .await?;
            }
        }
        RecommitteeMessage::NewUserReveal { proposed_share } => {
            recomm.revealed_shares.insert(proposed_share);
        }
        RecommitteeMessage::Begin {
            user,
            initiator,
            q,
            g,
            old_users,
        } => {
            if initiator != share_info.initiator
                || q != share_info.q_g.0
                || g != share_info.q_g.1
                || old_users != share_info.users
            {
                abort_recomm!()
            }
            if !recomm.new_users.is_empty() {
                abort_recomm!()
            }
            let active_users = connection.active_users(channel).await?;
            if active_users.len() < PARAMS.panic_threshold {
                error!("We are dropping like flies");
                db.remove(&ident);
                abort_recomm!()
            };
            let is_new_user = !old_users.contains(myself);
            if is_new_user {
                if user != myself {
                    abort_recomm!()
                }
            } else {
                let rs: Vec<_> = recomm
                    .revealed_shares
                    .iter()
                    .cloned()
                    .filter(|&s| {
                        let commit = share_info.q_g.1.modpow(&s.into(), &share_info.q_g.0);
                        recomm.commits.contains(&Some(commit))
                    })
                    .collect();
                if rs.len() < PARAMS.threshold {
                    abort_recomm!();
                }
                let r: usize = rs.into_iter().fold(0, |a, x| a ^ x).try_into().unwrap();
                let confirmed_user = &active_users[r % active_users.len()];
                if user != *confirmed_user {
                    abort_recomm!()
                }
            }
            recomm.new_users = share_info.users.clone();
            recomm.new_users.add(user);
            recomm.new_users.prune(&active_users);

            // Start actually blinding
            if !is_new_user {
                let (r_shares, r_commits) = generate_shares_and_commits(
                    recomm.blinders.my_r.clone(),
                    rng,
                    &share_info.q_g.0,
                    &share_info.q_g.1,
                );
                let (n_shares, n_commits) = generate_shares_and_commits(
                    &share_info.q_g.0 - &recomm.blinders.my_r,
                    rng,
                    &share_info.q_g.0,
                    &share_info.q_g.1,
                );
                if let Some((key, _)) = &share_info.share {
                    connection
                        .send_to_channel_and_enqueue_self(
                            myself,
                            channel,
                            &ProtocolMessage::Recommittee {
                                ident: ident.clone(),
                                nonce,
                                recomm_msg: RecommitteeMessage::NewGenCommits {
                                    key: *key,
                                    r_commits: r_commits.clone(),
                                    n_commits: n_commits.clone(),
                                },
                            },
                        )
                        .await?;
                }

                tokio::time::sleep(Duration::from_secs(3)).await;

                for (is_n, users, shares, commits) in [
                    (false, share_info.users.clone(), r_shares, r_commits),
                    (true, recomm.new_users.clone(), n_shares, n_commits),
                ] {
                    for (i, (user, share)) in users.into_iter().zip(shares.into_iter()).enumerate()
                    {
                        let key = i + 1;
                        if !is_share_valid(
                            &share_info.q_g.0,
                            &share_info.q_g.1,
                            &commits,
                            key,
                            &share,
                        ) {
                            abort_recomm!()
                        }
                        if let Some((from_key, _)) = &share_info.share {
                            connection
                                .send_dm_to(
                                    myself,
                                    &user,
                                    &ProtocolMessage::Recommittee {
                                        ident: ident.clone(),
                                        nonce,
                                        recomm_msg: RecommitteeMessage::NewGenShares {
                                            from_key: *from_key,
                                            key,
                                            value: share.clone(),
                                            is_n,
                                        },
                                    },
                                )
                                .await?;
                        }
                    }
                }
            }
        }
        RecommitteeMessage::NewGenCommits {
            key,
            r_commits,
            n_commits,
        } => {
            if key == 0 || key > share_info.users.len() {
                abort_recomm!()
            }
            if !share_info.users.user_is(key - 1, |u| u == &msg.from) {
                abort_recomm!()
            }
            if !recomm.blinders.r_commits[key].is_empty()
                || !recomm.blinders.n_commits[key].is_empty()
            {
                abort_recomm!()
            }
            if (&r_commits[0] * &n_commits[0]) % (&share_info.q_g.0 * 2u8 + 1u8) != 1u8.into() {
                abort_recomm!()
            }
            recomm.blinders.r_commits[key] = r_commits;
            recomm.blinders.n_commits[key] = n_commits;
        }
        RecommitteeMessage::NewGenShares {
            is_n,
            from_key,
            key,
            value,
        } => {
            if from_key == 0 || from_key > share_info.users.len() {
                abort_recomm!()
            }
            if !share_info.users.user_is(from_key - 1, |u| u == &msg.from) {
                abort_recomm!()
            }
            if recomm.blinders.r_commits[from_key].is_empty()
                || recomm.blinders.n_commits[from_key].is_empty()
            {
                abort_recomm!()
            }
            if (is_n && recomm.blinders.n_shares[from_key].is_some())
                || (!is_n && recomm.blinders.r_shares[from_key].is_some())
            {
                abort_recomm!()
            }
            let commits = if is_n {
                &recomm.blinders.n_commits[from_key]
            } else {
                if share_info.share.as_ref().is_none_or(|(k, _)| *k != key) {
                    abort_recomm!()
                }
                &recomm.blinders.r_commits[from_key]
            };
            if !is_share_valid(&share_info.q_g.0, &share_info.q_g.1, commits, key, &value) {
                abort_recomm!()
            }
            if is_n {
                recomm.blinders.n_shares[from_key] = Some((key, value));
            } else {
                recomm.blinders.r_shares[from_key] = Some((key, value));
            }
            let active_users = connection.active_users(channel).await?;
            let uncommitted: Vec<_> = (1..recomm.blinders.r_commits.len())
                .filter(|&i| recomm.blinders.r_commits[i].is_empty())
                .filter(|&i| {
                    share_info
                        .users
                        .user_is(i - 1, |u| active_users.contains(u))
                })
                .collect();
            if !recomm.blinding_released
                && uncommitted.is_empty()
                && !(0..recomm.blinders.r_commits.len())
                    .filter(|&i| !recomm.blinders.r_commits[i].is_empty())
                    .any(|i| {
                        share_info.share.as_ref().is_some_and(|(k, _)| {
                            recomm.blinders.r_shares[i]
                                .as_ref()
                                .is_none_or(|(rk, _)| rk != k)
                        })
                    })
            {
                if let Some((key, old_value)) = &share_info.share {
                    let value = recomm
                        .blinders
                        .r_shares
                        .iter()
                        .flatten()
                        .filter(|(k, _)| k == key)
                        .map(|(_, v)| v)
                        .chain([old_value])
                        .sum::<BigUint>()
                        % &share_info.q_g.0;
                    let key = *key;
                    let ident = ident.clone();
                    connection
                        .send_to_channel_and_enqueue_self(
                            myself,
                            channel,
                            &ProtocolMessage::Recommittee {
                                ident,
                                nonce,
                                recomm_msg: RecommitteeMessage::BlindedRelease { key, value },
                            },
                        )
                        .await?;
                }
                recomm.blinding_released = true;
            }
        }
        RecommitteeMessage::BlindedRelease { key, value } => {
            if key == 0 || key >= recomm.blinders.t_shares.len() {
                abort_recomm!()
            }
            if recomm.blinders.t_shares[key].is_some() {
                abort_recomm!()
            }
            recomm.blinders.t_shares[key] = Some(value);

            if recomm.blinders.t.is_none()
                && recomm.blinders.t_shares.iter().flatten().count() >= PARAMS.threshold
            {
                let t = recover_from_shares(&share_info.q_g.0, &recomm.blinders.t_shares);
                recomm.blinders.t = Some(t.clone());
                connection
                    .send_to_channel_and_enqueue_self(
                        myself,
                        channel,
                        &ProtocolMessage::Recommittee {
                            ident,
                            nonce,
                            recomm_msg: RecommitteeMessage::PublicRelease { t },
                        },
                    )
                    .await?;
            }
        }
        RecommitteeMessage::PublicRelease { t } => {
            if let Some(existing_t) = &recomm.blinders.t {
                if t != *existing_t {
                    abort_recomm!()
                }
            } else if recomm.blinders.t_shares.iter().flatten().count() >= PARAMS.threshold {
                let local_t = recover_from_shares(&share_info.q_g.0, &recomm.blinders.t_shares);
                if local_t != t {
                    abort_recomm!()
                } else {
                    recomm.blinders.t = Some(t);
                }
            } else {
                abort_recomm!()
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ShareInfo {
    users: Users,
    initiator: String,
    q_g: (BigUint, BigUint),
    commitments: Vec<BigUint>,
    share: Option<(usize, BigUint)>,
    released_share: HashMap<usize, BigUint>,
    recommitteeing: Option<RecommInfo>,
}

#[derive(Debug)]
struct RecommInfo {
    latest_message: Instant,
    nonce: u32,
    proposed_share: u64,
    commits: Vec<Option<BigUint>>,
    revealed_shares: HashSet<u64>,
    new_users: Users,
    blinders: Blinders,
    blinding_released: bool,
}

#[derive(Debug)]
struct Blinders {
    my_r: BigUint,
    r_commits: Vec<Vec<BigUint>>,
    r_shares: Vec<Option<(usize, BigUint)>>,
    n_commits: Vec<Vec<BigUint>>,
    n_shares: Vec<Option<(usize, BigUint)>>,
    t_shares: Vec<Option<BigUint>>,
    t: Option<BigUint>,
}

impl Blinders {
    fn new(my_r: BigUint, users_len: usize) -> Self {
        // NOTE: All of these have a `+1` to them due to keys starting at 1, rather than 0.
        Blinders {
            my_r,
            r_commits: vec![vec![]; users_len + 1],
            r_shares: vec![None; users_len + 1],
            n_commits: vec![vec![]; users_len + 1],
            n_shares: vec![None; users_len + 1],
            t_shares: vec![None; users_len + 1],
            t: None,
        }
    }

    fn into_share(self, q_g: &(BigUint, BigUint)) -> Option<(usize, BigUint)> {
        let q: BigInt = BigInt::from(q_g.0.clone());
        let (k, _) = self.n_shares.iter().flatten().next()?;

        let sn: BigInt = self
            .n_shares
            .iter()
            .flatten()
            .filter(|(ki, _)| ki == k)
            .map(|(_, v)| BigInt::from(v.clone()))
            .sum();

        let t = BigInt::from(self.t.as_ref().unwrap().clone());
        let v = ((&sn + &t) % &q + &q) % &q;

        assert!(BigInt::from(0) <= v, "{v} is not at least 0??!");
        assert!(v < q, "{v} is not less than q={q}??!");

        let v = BigUint::try_from(v).unwrap();
        debug!(k, ?v, "Converted to share");
        Some((*k, v))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Users {
    users: Vec<String>,
}

impl Users {
    fn new(users: Vec<String>) -> Self {
        Users { users }
    }

    fn add(&mut self, user: String) {
        self.users.push(user);
    }

    fn contains(&self, user: &str) -> bool {
        self.iter().any(|u| u == user)
    }

    fn len(&self) -> usize {
        self.users.len()
    }

    fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    fn user_is(&self, index: usize, f: impl FnOnce(&String) -> bool) -> bool {
        self.users.get(index).is_some_and(f)
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.users.iter()
    }

    fn into_iter(self) -> impl Iterator<Item = String> {
        self.users.into_iter()
    }

    fn all_active(&self, active_users: &[String]) -> bool {
        self.users.iter().all(|u| active_users.contains(u))
    }

    fn prune(&mut self, active_users: &[String]) {
        self.users.retain(move |u| active_users.contains(u));
    }
}

fn is_share_valid(
    q: &BigUint,
    g: &BigUint,
    commitments: &[BigUint],
    k: usize,
    v: &BigUint,
) -> bool {
    let p = q * 2u8 + 1u8;
    let lhs = g.modpow(v, &p);
    let rhs = commitments
        .iter()
        .enumerate()
        .map(|(i, c)| c.modpow(&BigUint::from(k).pow(i.try_into().unwrap()), &p))
        .product::<BigUint>()
        % p;
    let pass = lhs == rhs;
    trace!(%lhs, %rhs, %pass, "Share validity tested");
    pass
}

fn recover_from_shares(q: &BigUint, values: &[Option<BigUint>]) -> BigUint {
    let q = BigInt::from(q.clone());

    let mut r = BigInt::from(0);

    for (i, yi) in values.iter().enumerate().skip(1) {
        let Some(yi) = yi else {
            continue;
        };
        let mut t = BigInt::from(yi.clone());
        for (j, yj) in values.iter().enumerate().skip(1) {
            if j != i && yj.is_some() {
                t *= (BigInt::from(j)) * (BigInt::from(j) - BigInt::from(i)).modpow(&(&q - 2), &q);
                t %= q.clone();
                t += q.clone();
                t %= q.clone();
                assert!(BigInt::from(0) <= t, "{t} is not at least 0??!");
                assert!(t < q, "{t} is not less than q={q}??!");
            }
        }
        r += t;
        r %= q.clone();
    }

    assert!(BigInt::from(0) <= r);
    assert!(r < q);

    r.to_biguint().unwrap()
}
