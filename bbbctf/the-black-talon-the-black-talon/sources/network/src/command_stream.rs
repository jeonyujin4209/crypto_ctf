use anyhow::Result;
use common::{ClientCommand, ServerCommand};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, trace};

pub struct ReaderCommandStream {
    reader: BufReader<OwnedReadHalf>,
}

impl ReaderCommandStream {
    pub fn new(reader: OwnedReadHalf) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }

    pub async fn next_command(&mut self) -> Option<Result<ClientCommand, common::ParseError>> {
        loop {
            let mut buf = vec![];
            match self.reader.read_until(b'\n', &mut buf).await {
                Ok(0) => {
                    // EOF
                    return None;
                }
                Ok(1) => {
                    assert!(buf[0] == b'\n');
                    continue;
                }
                Ok(_len) => {}
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                    debug!("Connection reset");
                    return None;
                }
                Err(err) => panic!("Unexpected error while reading {err}"),
            }
            let cmd_str = String::from_utf8(buf);
            trace!(?cmd_str, "Reader command");
            let cmd: Result<ClientCommand, _> = cmd_str.ok()?.parse();
            if matches!(cmd, Ok(ClientCommand::Ping)) {
                // Just to be nicer at debug time
                trace!(?cmd, "Reader command");
            } else {
                debug!(?cmd, "Reader command");
            }
            return Some(cmd);
        }
    }
}

pub struct WriterCommandStream {
    writer: OwnedWriteHalf,
}

impl WriterCommandStream {
    pub fn new(writer: OwnedWriteHalf) -> Self {
        Self { writer }
    }

    pub async fn send_command(&mut self, cmd: ServerCommand) -> Result<()> {
        if matches!(cmd, ServerCommand::Pong) {
            // Just to be nicer at debug time
            trace!(?cmd, "Writer command");
        } else {
            debug!(?cmd, "Writer command");
        }
        Ok(self
            .writer
            .write_all((cmd.to_string() + "\n").as_bytes())
            .await?)
    }
}
