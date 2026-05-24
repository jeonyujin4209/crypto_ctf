use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Incorrect arguments (expected {expected}, found {found})")]
    IncorrectArguments { expected: usize, found: usize },
    #[error("Unparseable {input:?}")]
    Unparseable { input: String },
    #[error("Unexpected {input:?}")]
    Unexpected { input: String },
}

#[derive(Debug)]
pub enum ClientCommand {
    ConnectAs(String),
    ReconnectAs(String, String),
    ListChannels,
    ListUsers(String),
    JoinChannel(String),
    LeaveChannel(String),
    SendMessage(String, String),
    Ping,
    Goodbye,
}

impl std::str::FromStr for ClientCommand {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s_upper = s.to_uppercase();
        let spaces = s.chars().filter(|&c| c == ' ').count();
        if s_upper.starts_with("CONNECT") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::ConnectAs(arg.to_string()))
        } else if s_upper.starts_with("RECONNECT") {
            if spaces != 2 {
                return Err(ParseError::IncorrectArguments {
                    expected: 2,
                    found: spaces,
                });
            }
            let (_, args) = s.split_once(' ').unwrap();
            let (name, password) = args.split_once(' ').unwrap();
            Ok(Self::ReconnectAs(name.to_string(), password.to_string()))
        } else if s_upper.starts_with("LIST") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::ListChannels)
        } else if s_upper.starts_with("PEEK") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            if arg.starts_with('@') {
                return Err(ParseError::Unexpected { input: arg.into() });
            }
            Ok(Self::ListUsers(arg.to_string()))
        } else if s_upper.starts_with("JOIN") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            if arg.starts_with('@') {
                return Err(ParseError::Unexpected { input: arg.into() });
            }
            Ok(Self::JoinChannel(arg.to_string()))
        } else if s_upper.starts_with("LEAVE") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            if arg.starts_with('@') {
                return Err(ParseError::Unexpected { input: arg.into() });
            }
            Ok(Self::LeaveChannel(arg.to_string()))
        } else if s_upper.starts_with("MSG") {
            if spaces < 2 {
                return Err(ParseError::IncorrectArguments {
                    expected: 2,
                    found: spaces,
                });
            }
            let (_, args) = s.split_once(' ').unwrap();
            let (channel, message) = args.split_once(' ').unwrap();
            Ok(Self::SendMessage(channel.to_string(), message.to_string()))
        } else if s_upper.starts_with("PING") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::Ping)
        } else if s_upper.starts_with("GOODBYE") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::Goodbye)
        } else {
            Err(ParseError::Unparseable { input: s.into() })
        }
    }
}

impl std::fmt::Display for ClientCommand {
    #[allow(clippy::useless_format)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ConnectAs(name) => format!("CONNECT {name}"),
            Self::ReconnectAs(name, password) => format!("RECONNECT {name} {password}"),
            Self::ListChannels => format!("LIST"),
            Self::ListUsers(channel) => format!("PEEK {channel}"),
            Self::JoinChannel(channel) => format!("JOIN {channel}"),
            Self::LeaveChannel(channel) => format!("LEAVE {channel}"),
            Self::SendMessage(channel, message) => format!("MSG {channel} {message}"),
            Self::Ping => format!("PING"),
            Self::Goodbye => format!("GOODBYE"),
        };
        assert!(!s.contains('\n'));
        write!(f, "{s}")
    }
}

#[derive(Debug)]
pub enum ServerCommand {
    Welcome,
    ErrorContinue(String),
    ErrorQuit(String),
    SuccessQuit,
    NewUserCreated(String),
    YouAreNow(String),
    ChannelList(Vec<String>),
    UserList(Vec<String>),
    ChannelJoined(String),
    ChannelLeft(String),
    MessageReceived(String, String, String),
    Acknowledged,
    Pong,
}

impl std::str::FromStr for ServerCommand {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s_upper = s.to_uppercase();
        let spaces = s.chars().filter(|&c| c == ' ').count();
        if s_upper.starts_with("WELCOME") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::Welcome)
        } else if s_upper.starts_with("ERROR") {
            if spaces < 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::ErrorContinue(arg.to_string()))
        } else if s_upper.starts_with("FATAL") {
            if spaces < 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::ErrorQuit(arg.to_string()))
        } else if s_upper.starts_with("TATA_AND_FAREWELL") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::SuccessQuit)
        } else if s_upper.starts_with("NEWUSER") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::NewUserCreated(arg.to_string()))
        } else if s_upper.starts_with("CONNECTED") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::YouAreNow(arg.to_string()))
        } else if s_upper.starts_with("CHANNELS") {
            if spaces < 1 {
                return Ok(Self::ChannelList(vec![]));
            }
            let arg = s.split_once(' ').unwrap().1;
            let channels = arg.split(' ').map(|s| s.to_string()).collect();
            Ok(Self::ChannelList(channels))
        } else if s_upper.starts_with("USERS") {
            if spaces < 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            let users = arg.split(' ').map(|s| s.to_string()).collect();
            Ok(Self::UserList(users))
        } else if s_upper.starts_with("JOINED") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::ChannelJoined(arg.to_string()))
        } else if s_upper.starts_with("LEFT") {
            if spaces != 1 {
                return Err(ParseError::IncorrectArguments {
                    expected: 1,
                    found: spaces,
                });
            }
            let arg = s.split_once(' ').unwrap().1;
            Ok(Self::ChannelLeft(arg.to_string()))
        } else if s_upper.starts_with("MSGFROM") {
            if spaces < 3 {
                return Err(ParseError::IncorrectArguments {
                    expected: 3,
                    found: spaces,
                });
            }
            let (_, args) = s.split_once(' ').unwrap();
            let (channel, args) = args.split_once(' ').unwrap();
            let (user, message) = args.split_once(' ').unwrap();
            Ok(Self::MessageReceived(
                channel.to_string(),
                user.to_string(),
                message.to_string(),
            ))
        } else if s_upper.starts_with("ACK") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::Acknowledged)
        } else if s_upper.starts_with("PONG") {
            if spaces != 0 {
                return Err(ParseError::IncorrectArguments {
                    expected: 0,
                    found: spaces,
                });
            }
            Ok(Self::Pong)
        } else {
            Err(ParseError::Unparseable { input: s.into() })
        }
    }
}

impl std::fmt::Display for ServerCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Welcome => "WELCOME".to_string(),
            Self::ErrorContinue(reason) => {
                format!("ERROR {reason}")
            }
            Self::ErrorQuit(reason) => {
                format!("FATAL {reason}")
            }
            Self::SuccessQuit => "TATA_AND_FAREWELL".to_string(),
            Self::NewUserCreated(password) => {
                format!("NEWUSER {password}")
            }
            Self::YouAreNow(name) => {
                format!("CONNECTED {name}")
            }
            Self::ChannelList(channels) => format!("CHANNELS {}", channels.join(" ")),
            Self::UserList(users) => format!("USERS {}", users.join(" ")),
            Self::ChannelJoined(channel) => format!("JOINED {channel}"),
            Self::ChannelLeft(channel) => format!("LEFT {channel}"),
            Self::MessageReceived(channel, user, message) => {
                format!("MSGFROM {channel} {user} {message}")
            }
            Self::Acknowledged => "ACK".to_string(),
            Self::Pong => "PONG".to_string(),
        };
        assert!(!s.contains('\n'));
        write!(f, "{s}")
    }
}
