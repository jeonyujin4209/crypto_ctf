mod alive_connections;
mod broadcast;
mod command_stream;
mod network_state;
mod user;

use broadcast::BroadcastedMessage;
use command_stream::{ReaderCommandStream, WriterCommandStream};
use common::{ClientCommand, ServerCommand};
use network_state::NetworkState;
use user::User;

use anyhow::{Result, anyhow};
use clap::Parser;
use tokio::net::TcpStream;
use tracing::{info, instrument};

#[derive(Parser)]
struct CliArgs {
    /// Host to listen on
    #[clap(long, default_value = "127.0.0.1")]
    host: String,
    /// Port to listen on
    #[clap(long, default_value = "31337")]
    port: u16,
    #[clap(short = 'e', long)]
    enable_logging: bool,
    /// Verbose mode (repeat for more verbosity)
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
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

    info!("Starting listener on {}:{}", cli_args.host, cli_args.port);

    let listener = tokio::net::TcpListener::bind((cli_args.host, cli_args.port))
        .await
        .unwrap();

    let network_state = NetworkState::default();

    loop {
        let (stream, _socket_addr) = listener.accept().await.unwrap();
        let ns = network_state.clone();
        tokio::spawn(async move {
            process(stream, ns).await;
        });
    }
}

#[instrument(level = "trace")]
async fn process(socket: TcpStream, network_state: NetworkState) {
    let peer_addr = socket.peer_addr().unwrap();

    info!(%peer_addr, "Opened connection");

    let (mut reader, mut writer) = {
        let (reader, writer) = socket.into_split();
        (
            ReaderCommandStream::new(reader),
            WriterCommandStream::new(writer),
        )
    };

    writer.send_command(ServerCommand::Welcome).await.unwrap();

    let Some(Ok(cmd)) = reader.next_command().await else {
        writer
            .send_command(ServerCommand::ErrorQuit("Invalid command".into()))
            .await
            .unwrap();
        info!(%peer_addr, "Closed connection due to EOF or invalid command");
        return;
    };
    let user_id: usize = match cmd {
        ClientCommand::ConnectAs(name) => {
            let mut ns = network_state.write().await;
            if ns
                .users
                .iter()
                .any(|u| u.as_ref().map(|u| &u.name) == Some(&name))
            {
                writer
                    .send_command(ServerCommand::ErrorQuit("Name already in use".into()))
                    .await
                    .unwrap();
                return;
            }
            let user = User::new(name);
            writer
                .send_command(ServerCommand::NewUserCreated(user.password.clone()))
                .await
                .unwrap();
            let user_id = ns.users.len();
            ns.users.push(Some(user));
            user_id
        }
        ClientCommand::ReconnectAs(name, password) => {
            let mut ns = network_state.write().await;
            let id = ns
                .users
                .iter()
                .position(|u| u.as_ref().map(|u| &u.name) == Some(&name));
            if let Some(id) = id {
                if ns.users[id].as_mut().unwrap().check_password(&password) {
                    writer
                        .send_command(ServerCommand::YouAreNow(name.clone()))
                        .await
                        .unwrap();
                    id
                } else {
                    writer
                        .send_command(ServerCommand::ErrorQuit("Invalid password".into()))
                        .await
                        .unwrap();
                    return;
                }
            } else {
                writer
                    .send_command(ServerCommand::ErrorQuit("Invalid user".into()))
                    .await
                    .unwrap();
                return;
            }
        }
        _ => {
            writer
                .send_command(ServerCommand::ErrorQuit("Invalid command".into()))
                .await
                .unwrap();
            info!(%peer_addr, "Closed connection due to invalid initial command");
            return;
        }
    };
    let active_connection = {
        let mut ns = network_state.write().await;
        ns.active_connections.connect(peer_addr, user_id)
    };

    let mut subscriber = network_state.read().await.broadcast.subscribe();

    loop {
        enum NextStep {
            Command(Result<ClientCommand, common::ParseError>),
            Broadcast(BroadcastedMessage),
            Shutdown,
        }
        let next_step = tokio::select! {
            cmd = reader.next_command() => match cmd {
                Some(cmd) => NextStep::Command(cmd),
                None => NextStep::Shutdown,
            },
            Ok(msg) = subscriber.recv() => NextStep::Broadcast(msg),
            else => unreachable!(),
        };
        let cmd = match next_step {
            NextStep::Shutdown => break,
            NextStep::Broadcast(BroadcastedMessage {
                from,
                channel,
                message,
            }) => {
                let ns = network_state.read().await;
                let dm_target = channel.starts_with('@')
                    && ns.users[user_id]
                        .as_ref()
                        .is_some_and(|u| u.name == channel[1..]);
                let in_channel = ns
                    .channels
                    .get(&channel)
                    .is_some_and(|ch| ch.users.contains(&user_id));
                if (dm_target || in_channel)
                    && Some(&from) != ns.users[user_id].as_ref().map(|u| &u.name)
                {
                    let channel = if dm_target { "@".into() } else { channel };
                    writer
                        .send_command(ServerCommand::MessageReceived(channel, from, message))
                        .await
                        .unwrap();
                }
                continue;
            }
            NextStep::Command(Ok(cmd)) => cmd,
            NextStep::Command(Err(error)) => {
                writer
                    .send_command(ServerCommand::ErrorContinue(error.to_string()))
                    .await
                    .unwrap();
                continue;
            }
        };
        match cmd {
            ClientCommand::ConnectAs(_) | ClientCommand::ReconnectAs(_, _) => {
                writer
                    .send_command(ServerCommand::ErrorQuit("Already connected".into()))
                    .await
                    .unwrap();
                break;
            }
            ClientCommand::ListChannels => {
                let ns = network_state.read().await;
                let channels = ns.channels.keys().cloned().collect();
                writer
                    .send_command(ServerCommand::ChannelList(channels))
                    .await
                    .unwrap();
            }
            ClientCommand::ListUsers(channel) => {
                let ns = network_state.write().await;
                if let Some(ch) = ns.channels.get(&channel) {
                    if ch.users.contains(&user_id) {
                        let users = ch
                            .users
                            .iter()
                            .cloned()
                            .filter(|&u| ns.active_connections.is_connected(u))
                            .filter_map(|u| ns.users.get(u)?.as_ref()?.name.clone().into())
                            .collect();
                        writer
                            .send_command(ServerCommand::UserList(users))
                            .await
                            .unwrap();
                    } else {
                        writer
                            .send_command(ServerCommand::ErrorContinue("Not in channel".into()))
                            .await
                            .unwrap();
                    }
                } else {
                    writer
                        .send_command(ServerCommand::ErrorContinue("No such channel".into()))
                        .await
                        .unwrap();
                }
            }
            ClientCommand::JoinChannel(channel) => {
                let mut ns = network_state.write().await;
                let ch = ns.channels.entry(channel.clone()).or_default();
                if ch.users.contains(&user_id) {
                    writer
                        .send_command(ServerCommand::ErrorContinue("Already in channel".into()))
                        .await
                        .unwrap();
                } else {
                    ch.users.push(user_id);
                    writer
                        .send_command(ServerCommand::ChannelJoined(channel.clone()))
                        .await
                        .unwrap();
                }
            }
            ClientCommand::LeaveChannel(channel) => {
                let mut ns = network_state.write().await;
                let ch = ns.channels.entry(channel.clone()).or_default();
                if let Some(pos) = ch.users.iter().position(|&u| u == user_id) {
                    ch.users.remove(pos);
                    writer
                        .send_command(ServerCommand::ChannelLeft(channel.clone()))
                        .await
                        .unwrap();
                } else {
                    writer
                        .send_command(ServerCommand::ErrorContinue("Not in channel".into()))
                        .await
                        .unwrap();
                }
                if ch.users.is_empty() {
                    ns.channels.remove(&channel);
                }
            }
            ClientCommand::SendMessage(channel, message) => {
                let ns = network_state.read().await;
                let no_target_error = if channel.starts_with('@') {
                    (!ns.users
                        .iter()
                        .any(|u| u.as_ref().is_some_and(|u| u.name == channel[1..])))
                    .then_some("No such user")
                } else {
                    (!ns.channels
                        .get(&channel)
                        .is_some_and(|ch| ch.users.contains(&user_id)))
                    .then_some("Not in channel")
                };
                if let Some(err) = no_target_error {
                    writer
                        .send_command(ServerCommand::ErrorContinue(err.into()))
                        .await
                        .unwrap();
                    continue;
                };
                ns.broadcast.send(BroadcastedMessage {
                    from: ns.users[user_id].as_ref().map(|u| u.name.clone()).unwrap(),
                    channel,
                    message,
                });
                writer
                    .send_command(ServerCommand::Acknowledged)
                    .await
                    .unwrap();
            }
            ClientCommand::Ping => {
                writer.send_command(ServerCommand::Pong).await.unwrap();
            }
            ClientCommand::Goodbye => {
                writer
                    .send_command(ServerCommand::SuccessQuit)
                    .await
                    .unwrap();
                break;
            }
        }
    }

    active_connection.disconnect();
}
