use common::{ClientCommand, ServerCommand};

use anyhow::{Result, anyhow};
use clap::Parser;
use rand::prelude::*;
use tracing::{Instrument, debug, info, info_span};

use crate::connection::Connection;

#[derive(Parser, Debug, Clone)]
struct CliArgs {
    /// Server to connect to
    #[clap(long, default_value = "127.0.0.1")]
    server: String,
    /// Port to connect to
    #[clap(long, default_value = "31337")]
    port: u16,
    #[clap(short = 'e', long)]
    enable_logging: bool,
    /// Verbose mode (repeat for more verbosity)
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Username
    #[clap(short = 'u', long, required_unless_present = "multiple_clients")]
    username: Option<String>,
    /// Password
    #[clap(long)]
    password: Option<String>,
    /// Secret
    #[clap(long, conflicts_with = "request_release")]
    secret: Option<String>,
    /// Force a specific user onto the committee
    #[clap(long, requires = "secret")]
    force_user: Option<String>,
    /// Request release of shares for a given secret identifier
    #[clap(long, conflicts_with = "secret")]
    request_release: Option<String>,
    /// Channel
    #[clap(long)]
    channel: String,
    /// Spin up N users in a single process, automatically picking usernames
    #[clap(
        short = 'm',
        long,
        value_name = "N",
        conflicts_with = "username",
        conflicts_with = "password",
        conflicts_with = "secret",
        conflicts_with = "request_release"
    )]
    multiple_clients: Option<usize>,
}

pub(crate) async fn main() -> Result<()> {
    let cli_args = CliArgs::parse();
    if cli_args.enable_logging {
        tracing_subscriber::fmt()
            .with_max_level(match cli_args.verbose {
                0 => tracing::Level::INFO,
                1 => tracing::Level::DEBUG,
                2 => tracing::Level::TRACE,
                _ => {
                    return Err(anyhow!("Invalid verbosity, only up to 2 supported"));
                }
            })
            .init();
    }

    let mut rng = thread_rng();

    if let Some(n) = cli_args.multiple_clients {
        let mut handles = vec![];
        for i in 0..n {
            let mut client_args = cli_args.clone();
            client_args.multiple_clients = None;

            let ident_tag: String = if cfg!(debug_assertions) {
                "bot".into()
            } else {
                (0..4)
                    .map(|_| {
                        let choices = "ghijklmnopqrstuvwxyz";
                        choices.chars().choose(&mut rng).unwrap()
                    })
                    .collect()
            };

            client_args.username = Some(format!("{ident_tag}_{i}"));

            let span = info_span!("m", u = %client_args.username.as_ref().unwrap());
            handles.push(tokio::spawn(async {
                async move { real_main(client_args).await }
                    .instrument(span)
                    .await
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        Ok(())
    } else {
        real_main(cli_args).await
    }
}

async fn real_main(cli_args: CliArgs) -> Result<()> {
    debug!(?cli_args, "Starting client");

    let mut connection = Connection::connect(&cli_args.server, cli_args.port).await?;

    match connection.recv_cmd().await? {
        ServerCommand::Welcome => {}
        cmd => panic!("Invalid command from server: {cmd:?}"),
    }

    let username = cli_args.username.unwrap();
    connection
        .send(match cli_args.password {
            None => ClientCommand::ConnectAs(username.clone()),
            Some(pass) => ClientCommand::ReconnectAs(username.clone(), pass),
        })
        .await?;
    match connection.recv_cmd().await? {
        ServerCommand::NewUserCreated(password) => {
            info!(password, "User created");
        }
        ServerCommand::YouAreNow(_) => {}
        cmd => panic!("Invalid command from server: {cmd:?}"),
    }

    connection
        .send(ClientCommand::JoinChannel(cli_args.channel.clone()))
        .await?;
    match connection.recv_cmd().await? {
        ServerCommand::ErrorContinue(err) => {
            if err != "Already in channel" {
                panic!("Unexpected error {err:?}");
            }
        }
        ServerCommand::ChannelJoined(_) => {}
        cmd => panic!("Invalid command from server: {cmd:?}"),
    }

    if let Some(secret) = cli_args.secret {
        crate::inject_secret(
            &mut connection,
            crate::InjectSecret {
                user: &username,
                secret: &secret,
                channel: &cli_args.channel,
                forced_user: cli_args.force_user.as_deref(),
            },
        )
        .await?;
    } else if let Some(ident) = cli_args.request_release {
        crate::request_release(
            &mut connection,
            crate::RequestRelease {
                user: &username,
                ident: &ident,
                channel: &cli_args.channel,
            },
        )
        .await?;
    } else {
        crate::general_user(
            &mut connection,
            crate::GeneralUser {
                user: &username,
                channel: &cli_args.channel,
            },
        )
        .await?;
    }

    Ok(())
}
