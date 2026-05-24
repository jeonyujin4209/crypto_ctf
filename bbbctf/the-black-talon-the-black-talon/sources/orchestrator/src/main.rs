use anyhow::Result;
use clap::Parser;
use rand::prelude::*;
use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::{debug, info, trace, warn};

fn normalize_cwd() -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path.parent().unwrap();
    std::env::set_current_dir(exe_dir)?;
    Ok(())
}

#[derive(Parser)]
struct CliArgs {
    /// Verbose mode (repeat for more verbosity)
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn read_string(stdout: &mut std::process::ChildStdout) -> String {
    let mut buf = vec![0u8; 1024];
    let len = stdout.read(&mut buf).unwrap();
    buf.resize(len, 0u8);
    String::from_utf8(buf).unwrap()
}

fn connect_to_stdin_stdout(
    mut child_stdin: std::process::ChildStdin,
    child_stdout: std::process::ChildStdout,
) {
    let dead = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let in_thread = std::thread::spawn({
        let dead = std::sync::Arc::clone(&dead);
        move || {
            let mut stdin = nonblock::NonBlockingReader::from_fd(std::io::stdin().lock()).unwrap();
            'outer: while !dead.load(std::sync::atomic::Ordering::Relaxed) {
                let mut buf = vec![];
                let len = stdin.read_available(&mut buf).unwrap();
                if stdin.is_eof() {
                    break;
                }
                let mut remaining = &buf[..len];
                while !remaining.is_empty() {
                    match child_stdin.write(remaining) {
                        Ok(n) => remaining = &remaining[n..],
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            break 'outer;
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            let _ = stdin.into_blocking().unwrap();
            dead.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });
    let out_thread = std::thread::spawn({
        let dead = std::sync::Arc::clone(&dead);
        move || {
            let mut child_stdout = nonblock::NonBlockingReader::from_fd(child_stdout).unwrap();
            'outer: while !dead.load(std::sync::atomic::Ordering::Relaxed) {
                let mut buf = vec![];
                let len = child_stdout.read_available(&mut buf).unwrap();
                if child_stdout.is_eof() {
                    break;
                }
                let mut remaining = &buf[..len];
                while !remaining.is_empty() {
                    match std::io::stdout().write(remaining) {
                        Ok(n) => remaining = &remaining[n..],
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            break 'outer;
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            dead.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });
    in_thread.join().unwrap();
    out_thread.join().unwrap();
}

fn main() -> Result<()> {
    normalize_cwd()?;

    let cli_args = CliArgs::parse();
    tracing_subscriber::fmt()
        .event_format(
            tracing_subscriber::fmt::format()
                .with_target(false)
                .with_timer(tracing_subscriber::fmt::time::uptime()),
        )
        .with_max_level(match cli_args.verbose {
            0 => tracing::Level::INFO,
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .init();

    let mut rng = rand::thread_rng();

    // 1024 to 49151 are the User Ports; but we are being more conservative here.
    let port: u16 = rng.gen_range(30_000..40_000);
    debug!(port, "Spinning up network");
    info!("Smoke curls from the saloon chimney as the town stirs to life.");

    let mut network = Command::new("./network")
        .args(["--host", "127.0.0.1"])
        .args(["--port", &port.to_string()])
        .args(vec!["-v"; cli_args.verbose.saturating_sub(1).into()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    std::thread::sleep(Duration::from_secs(1));

    let saloon = [
        "the-black-vulture",
        "the-coyotes-den",
        "the-dead-mans-pour",
        "the-devils-ledger",
        "the-hollow-oak-saloon",
        "the-iron-flask",
        "the-midnight-gambler",
        "the-rustlers-refuge",
        "the-silent-rider",
        "the-whispering-knife",
        "the-whispering-spurs",
    ]
    .choose(&mut rng)
    .unwrap();
    info!(saloon, "The air smells of tobacco, blood, and old secrets.");

    std::thread::sleep(Duration::from_secs(1));

    let protagonist = [
        "bloodmouth",
        "cold_iron",
        "deadeye",
        "hollow_eyes",
        "six_toe",
        "the_black_hand",
        "the_drifter",
        "the_gravedigger",
        "the_vulture",
        "whisper",
    ]
    .choose(&mut rng)
    .unwrap();
    info!(
        protagonist,
        "The piano stops mid-note as you walk in, coat dragging dust behind you."
    );
    let mut player = Command::new("nc")
        .args(["127.0.0.1", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut player_stdin = player.stdin.take().unwrap();
    let mut player_stdout = player.stdout.take().unwrap();
    assert_eq!(read_string(&mut player_stdout), "WELCOME\n");
    writeln!(player_stdin, "CONNECT {protagonist}").unwrap();
    let player_password = read_string(&mut player_stdout)
        .split_once("NEWUSER ")
        .unwrap()
        .1
        .trim()
        .to_owned();
    writeln!(player_stdin, "JOIN {saloon}").unwrap();
    assert_eq!(
        read_string(&mut player_stdout),
        format!("JOINED {saloon}\n")
    );
    debug!(
        name = protagonist,
        password = player_password,
        "Initiated the protagonist"
    );

    std::thread::sleep(Duration::from_secs(1));

    info!("The dealer smirks like he already knows how the night ends.");
    let mut bots = Command::new("./client")
        .args(["--server", "127.0.0.1"])
        .args(["--port", &port.to_string()])
        .args(vec!["-v"; cli_args.verbose.saturating_sub(1).into()])
        .args(["--channel", saloon])
        .args(["--multiple-clients", "50"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    std::thread::sleep(Duration::from_secs(1));

    let secret: String = (0..64)
        .map(|_| {
            let choices = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            choices.chars().choose(&mut rng).unwrap()
        })
        .collect();
    debug!(secret, "Injecting secret");
    let sheriff = [
        "brass_heart",
        "buckshot_bill",
        "good_as_gold",
        "iron_will",
        "old_steady",
        "pure_grit",
        "silver_star",
        "steady_hand",
        "sweetwater_sam",
        "the_preacher",
        "the_unbroken",
        "true_north",
    ]
    .choose(&mut rng)
    .unwrap();
    info!(
        sheriff,
        "A few names are muttered, a warning or a prayer---and with scarcely a goodbye, the sheriff steps off the boardwalk and out of town, like a man leaving something half-finished."
    );
    let mut secret_injector = Command::new("./client")
        .args(["--server", "127.0.0.1"])
        .args(["--port", &port.to_string()])
        .args(vec!["-v"; cli_args.verbose.saturating_sub(1).into()])
        .args(["--channel", saloon])
        .args(["--force-user", protagonist])
        .args(["--username", sheriff])
        .args(["--secret", &secret])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    trace!(?secret_injector, "Injected secrets");

    info!("What do you do?");
    connect_to_stdin_stdout(player_stdin, player_stdout);

    assert!(player.wait().unwrap().success());

    secret_injector.kill().unwrap();
    secret_injector.wait().unwrap();
    bots.kill().unwrap();
    bots.wait().unwrap();
    network.kill().unwrap();
    network.wait().unwrap();

    info!(
        "The sheriff's back---no words, no welcome, just that look he gives when he's deciding if you belong here, or don't."
    );
    info!("What do you do?");
    let guess = {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_owned()
    };
    if guess == secret {
        let flag = std::fs::read_to_string("./flag").expect(
            "Contact admins if this fails on the server; \
             if it fails locally, just make a ./flag file \
             in the same directory as the orchestrator",
        );
        info!(
            flag,
            "Every ghost in this town knows your name now---the flag is yours, for better or worse"
        );
    } else {
        warn!("Ain't your kind of place, and we aim to keep it that way.");
        warn!("Keep on movin'");
    }

    Ok(())
}
