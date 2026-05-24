use std::{collections::VecDeque, time::Duration};

use common::{ClientCommand, ServerCommand};

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, trace};

use crate::ProtocolMessage;

#[derive(Clone, Default, Debug)]
pub(crate) struct Message {
    pub(crate) from: String,
    pub(crate) channel: String,
    pub(crate) message: String,
}

pub(crate) struct Connection {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    received_cmds: VecDeque<ServerCommand>,
    received_messages: VecDeque<Message>,
}

impl Connection {
    pub(crate) async fn connect(server: &str, port: u16) -> Result<Self> {
        match tokio::net::TcpStream::connect((server, port)).await {
            Ok(conn) => {
                let (reader, writer) = conn.into_split();
                let reader = BufReader::new(reader);
                Ok(Self {
                    reader,
                    writer,
                    received_cmds: Default::default(),
                    received_messages: Default::default(),
                })
            }
            Err(reason) => {
                error!(server, port, %reason, "Could not connect");
                Err(reason)?
            }
        }
    }

    pub(crate) async fn recv_arb_server_cmd(&mut self) -> Result<ServerCommand> {
        let mut buf = vec![];
        let num_bytes = self.reader.read_until(b'\n', &mut buf).await?;
        if num_bytes == 0 {
            // EOF
            error!("EOF");
            anyhow::bail!("EOF from server")
        } else {
            let buf = String::from_utf8(buf);
            trace!(?buf, "Server command");
            let cmd = buf?.parse()?;
            if matches!(cmd, ServerCommand::Pong) {
                // Reduce noise in debug mode
                trace!(?cmd, "Server command");
            } else {
                debug!(?cmd, "Server command");
            }
            Ok(cmd)
        }
    }

    pub(crate) fn recv_immediately_if(
        &mut self,
        predicate: fn(&ServerCommand) -> bool,
    ) -> Option<ServerCommand> {
        for i in 0..self.received_cmds.len() {
            if predicate(&self.received_cmds[i]) {
                return Some(self.received_cmds.remove(i).unwrap());
            }
        }
        None
    }

    pub(crate) async fn recv_if(
        &mut self,
        predicate: fn(&ServerCommand) -> bool,
    ) -> Result<ServerCommand> {
        if let Some(cmd) = self.recv_immediately_if(predicate) {
            return Ok(cmd);
        }
        loop {
            let cmd = self.recv_arb_server_cmd().await?;
            if predicate(&cmd) {
                return Ok(cmd);
            } else {
                self.received_cmds.push_back(cmd);
            }
        }
    }

    pub(crate) async fn try_block_to_refill_recv_buffer(
        &mut self,
        duration: Duration,
    ) -> Result<()> {
        tokio::time::timeout(duration, self.block_to_refill_recv_buffer())
            .await
            .unwrap_or(Ok(()))
    }

    pub(crate) async fn block_to_refill_recv_buffer(&mut self) -> Result<()> {
        let cmd = self.recv_arb_server_cmd().await?;
        self.received_cmds.push_back(cmd);
        Ok(())
    }

    pub(crate) async fn recv_cmd(&mut self) -> Result<ServerCommand> {
        self.recv_if(|cmd| !matches!(cmd, ServerCommand::MessageReceived(_, _, _)))
            .await
    }

    pub(crate) fn enqueue_message_to_self_raw(&mut self, m: Message) {
        self.received_messages.push_back(m);
    }

    pub(crate) fn next_message(&mut self) -> Option<Message> {
        if let Some(m) = self.received_messages.pop_front() {
            return Some(m);
        }
        match self
            .recv_immediately_if(|cmd| matches!(cmd, ServerCommand::MessageReceived(_, _, _)))?
        {
            ServerCommand::MessageReceived(channel, from, message) => Some(Message {
                from,
                channel,
                message,
            }),
            _ => unreachable!(),
        }
    }

    pub(crate) async fn send(&mut self, cmd: ClientCommand) -> Result<()> {
        if matches!(cmd, ClientCommand::Ping) {
            // Reduce noise in debug mode
            trace!(?cmd, "Client command");
        } else {
            debug!(?cmd, "Client command");
        }
        self.writer
            .write_all((cmd.to_string() + "\n").as_bytes())
            .await?;
        Ok(())
    }

    pub(crate) async fn send_raw_message_to(&mut self, to: &str, message: &str) -> Result<()> {
        self.send(ClientCommand::SendMessage(to.into(), message.into()))
            .await?;
        match self.recv_cmd().await? {
            ServerCommand::Acknowledged => Ok(()),
            cmd => panic!("Unexpected command from server {cmd:?}"),
        }
    }

    pub(crate) async fn send_dm_to(
        &mut self,
        myself: &str,
        to: &str,
        message: &ProtocolMessage,
    ) -> Result<()> {
        if myself == to {
            self.enqueue_self(myself, "@", message);
            Ok(())
        } else {
            self.send_raw_message_to(&format!("@{to}"), &message.to_string())
                .await
        }
    }

    pub(crate) async fn send_to_channel(
        &mut self,
        _myself: &str,
        channel: &str,
        message: &ProtocolMessage,
    ) -> Result<()> {
        self.send_raw_message_to(channel, &message.to_string())
            .await
    }

    fn enqueue_self(&mut self, myself: &str, channel: &str, message: &ProtocolMessage) {
        self.enqueue_message_to_self_raw(Message {
            from: myself.into(),
            channel: channel.into(),
            message: message.to_string(),
        })
    }

    pub(crate) async fn send_to_channel_and_enqueue_self(
        &mut self,
        myself: &str,
        channel: &str,
        message: &ProtocolMessage,
    ) -> Result<()> {
        self.enqueue_self(myself, channel, message);
        self.send_to_channel(myself, channel, message).await
    }

    pub(crate) async fn active_users(
        &mut self,
        channel: &str,
    ) -> Result<Vec<String>, anyhow::Error> {
        let active_users = {
            self.send(ClientCommand::ListUsers(channel.into())).await?;
            let ServerCommand::UserList(users) = self
                .recv_if(|p| matches!(p, ServerCommand::UserList(_)))
                .await?
            else {
                unreachable!()
            };
            users
        };
        Ok(active_users)
    }
}
