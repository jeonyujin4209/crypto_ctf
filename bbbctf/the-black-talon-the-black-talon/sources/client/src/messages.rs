use crate::Users;
use anyhow::Result;
use num_bigint::BigUint;

pub(crate) enum ProtocolMessage {
    Share {
        ident: String,
        key: usize,
        value: BigUint,
    },
    Release {
        ident: String,
    },
    ReleasedShare {
        ident: String,
        key: usize,
        value: BigUint,
        q: BigUint,
        g: BigUint,
    },
    Commitments {
        ident: String,
        q_g: (BigUint, BigUint),
        commitments: Vec<BigUint>,
        users: Users,
    },
    Recommittee {
        ident: String,
        nonce: u32,
        recomm_msg: RecommitteeMessage,
    },
}

pub(crate) enum RecommitteeMessage {
    Propose,
    Abort {
        blame: String,
    },
    NewUserCommit {
        commit: BigUint,
    },
    NewUserReveal {
        proposed_share: u64,
    },
    Begin {
        user: String,
        initiator: String,
        q: BigUint,
        g: BigUint,
        old_users: Users,
    },
    NewGenCommits {
        key: usize,
        r_commits: Vec<BigUint>,
        n_commits: Vec<BigUint>,
    },
    NewGenShares {
        is_n: bool,
        from_key: usize,
        key: usize,
        value: BigUint,
    },
    BlindedRelease {
        key: usize,
        value: BigUint,
    },
    PublicRelease {
        t: BigUint,
    },
}

impl std::fmt::Display for ProtocolMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolMessage::Share { ident, key, value } => {
                let value = value.to_str_radix(36);
                write!(f, "SHARE {ident} {key} {value}")
            }
            ProtocolMessage::Release { ident } => write!(f, "RELEASE {ident}"),
            ProtocolMessage::ReleasedShare {
                ident,
                key,
                value,
                q,
                g,
            } => {
                let value = value.to_str_radix(36);
                let q = q.to_str_radix(36);
                let g = g.to_str_radix(36);
                write!(f, "RELEASED {ident} {key} {value} {q} {g}")
            }
            ProtocolMessage::Commitments {
                ident,
                q_g: (q, g),
                commitments,
                users,
            } => {
                let q = q.to_str_radix(36);
                let g = g.to_str_radix(36);
                let commitments = commitments
                    .iter()
                    .map(|x| x.to_str_radix(36))
                    .collect::<Vec<_>>()
                    .join(",");
                let users = users
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                write!(f, "COMMITMENTS {ident} {q} {g} {commitments} {users}")
            }
            ProtocolMessage::Recommittee {
                ident,
                nonce,
                recomm_msg,
            } => {
                write!(f, "RECOMM {ident} {nonce} {recomm_msg}")
            }
        }
    }
}

impl std::fmt::Display for RecommitteeMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommitteeMessage::Propose => write!(f, "PROPOSE"),
            RecommitteeMessage::Abort { blame } => {
                write!(f, "JACCUSE {blame}")
            }
            RecommitteeMessage::NewUserCommit { commit } => {
                let commit = commit.to_str_radix(36);
                write!(f, "NUC {commit}")
            }
            RecommitteeMessage::NewUserReveal { proposed_share } => {
                write!(f, "NUR {proposed_share}")
            }
            RecommitteeMessage::Begin {
                user,
                initiator,
                q,
                g,
                old_users,
            } => {
                let q = q.to_str_radix(36);
                let g = g.to_str_radix(36);
                let old_users = old_users
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                write!(f, "BEGIN {user} {initiator} {q} {g} {old_users}")
            }
            RecommitteeMessage::NewGenCommits {
                key,
                r_commits,
                n_commits,
            } => {
                let r_commits = r_commits
                    .iter()
                    .map(|x| x.to_str_radix(36))
                    .collect::<Vec<_>>()
                    .join(",");
                let n_commits = n_commits
                    .iter()
                    .map(|x| x.to_str_radix(36))
                    .collect::<Vec<_>>()
                    .join(",");
                write!(f, "NGC {key} {r_commits} {n_commits}")
            }
            RecommitteeMessage::NewGenShares {
                is_n,
                from_key,
                key,
                value,
            } => {
                let value = value.to_str_radix(36);
                write!(
                    f,
                    "NGS {from_key} {key} {value} {}",
                    if *is_n { "N" } else { "R" }
                )
            }
            RecommitteeMessage::BlindedRelease { key, value } => {
                let value = value.to_str_radix(36);
                write!(f, "BR {key} {value}")
            }
            RecommitteeMessage::PublicRelease { t } => {
                let t = t.to_str_radix(36);
                write!(f, "PR {t}")
            }
        }
    }
}

impl std::str::FromStr for ProtocolMessage {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split(' ');
        match s.next().ok_or(())? {
            "SHARE" => {
                let ident = s.next().ok_or(())?.to_owned();
                let key = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let value = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                if s.next().is_some() {
                    return Err(());
                }
                Ok(Self::Share { ident, key, value })
            }
            "RELEASE" => {
                let ident = s.next().ok_or(())?.to_owned();
                Ok(Self::Release { ident })
            }
            "RELEASED" => {
                let ident = s.next().ok_or(())?.to_owned();
                let key = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let value = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let q = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let g = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                if s.next().is_some() {
                    return Err(());
                }
                Ok(Self::ReleasedShare {
                    ident,
                    key,
                    value,
                    q,
                    g,
                })
            }
            "COMMITMENTS" => {
                let ident = s.next().ok_or(())?.to_owned();
                let q = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let g = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let commitments = s
                    .next()
                    .ok_or(())?
                    .split(',')
                    .map(|x| BigUint::parse_bytes(x.as_bytes(), 36))
                    .collect::<Option<_>>()
                    .ok_or(())?;
                let users = Users::new(
                    s.next()
                        .ok_or(())?
                        .split(',')
                        .map(|x| x.to_owned())
                        .collect(),
                );
                Ok(Self::Commitments {
                    ident,
                    q_g: (q, g),
                    commitments,
                    users,
                })
            }
            "RECOMM" => {
                let ident = s.next().ok_or(())?.to_owned();
                let nonce = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let recomm_msg = s.collect::<Vec<_>>().join(" ").parse()?;
                Ok(Self::Recommittee {
                    ident,
                    nonce,
                    recomm_msg,
                })
            }
            _ => Err(()),
        }
    }
}

impl std::str::FromStr for RecommitteeMessage {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split(' ');
        match s.next().ok_or(())? {
            "PROPOSE" => Ok(Self::Propose),
            "JACCUSE" => {
                let blame = s.next().ok_or(())?.to_owned();
                Ok(Self::Abort { blame })
            }
            "NUC" => {
                let commit = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                Ok(Self::NewUserCommit { commit })
            }
            "NUR" => {
                let proposed_share = s.next().ok_or(())?.parse().map_err(|_| ())?;
                Ok(Self::NewUserReveal { proposed_share })
            }
            "BEGIN" => {
                let user = s.next().ok_or(())?.to_owned();
                let initiator = s.next().ok_or(())?.to_owned();
                let q = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let g = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let old_users = Users::new(
                    s.next()
                        .ok_or(())?
                        .split(',')
                        .map(|x| x.to_owned())
                        .collect(),
                );
                Ok(Self::Begin {
                    user,
                    initiator,
                    q,
                    g,
                    old_users,
                })
            }
            "NGC" => {
                let key = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let r_commits = s
                    .next()
                    .ok_or(())?
                    .split(',')
                    .map(|x| BigUint::parse_bytes(x.as_bytes(), 36))
                    .collect::<Option<_>>()
                    .ok_or(())?;
                let n_commits = s
                    .next()
                    .ok_or(())?
                    .split(',')
                    .map(|x| BigUint::parse_bytes(x.as_bytes(), 36))
                    .collect::<Option<_>>()
                    .ok_or(())?;
                Ok(Self::NewGenCommits {
                    key,
                    r_commits,
                    n_commits,
                })
            }
            "NGS" => {
                let from_key = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let key = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let value = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                let is_n = s.next().ok_or(())? == "N";
                Ok(Self::NewGenShares {
                    from_key,
                    key,
                    value,
                    is_n,
                })
            }
            "BR" => {
                let key = s.next().ok_or(())?.parse().map_err(|_| ())?;
                let value = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                Ok(Self::BlindedRelease { key, value })
            }
            "PR" => {
                let t = BigUint::parse_bytes(s.next().ok_or(())?.as_bytes(), 36).ok_or(())?;
                Ok(Self::PublicRelease { t })
            }
            _ => Err(()),
        }
    }
}
