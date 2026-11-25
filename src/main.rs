mod auth;
mod mint;
mod proto;

use clap::Parser;
use std::{io, path::PathBuf, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::watch,
    time::{sleep, timeout},
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(
    version,
    about = "Serve a local ISO as legacy ATEN virtual CD-ROM media (no KVM)"
)]
struct Args {
    #[arg(long)]
    host: String,
    #[arg(
        long,
        required_unless_present = "token_pair",
        conflicts_with = "token_pair"
    )]
    user: Option<String>,
    #[arg(
        long,
        required_unless_present = "token_pair",
        conflicts_with = "token_pair"
    )]
    pass: Option<String>,
    #[arg(long, num_args = 2, value_names = ["USER_TOKEN", "PASS_TOKEN"])]
    token_pair: Option<Vec<String>>,
    #[arg(long)]
    #[arg(required_unless_present = "eject", conflicts_with = "eject")]
    iso: Option<PathBuf>,
    /// Zero-based virtual media slot
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=2))]
    slot: u8,
    /// Override the JNLP vUSB port (default 623 when using --token-pair)
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    port: Option<u16>,
    /// Mount nothing: authenticate and send an explicit unmount for the slot,
    /// clearing a stale registration left by a killed session (--iso not needed)
    #[arg(long)]
    eject: bool,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!("aten-vm: {error}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<()> {
    let base = mint::base_url(&args.host)?;
    let host = base
        .host_str()
        .unwrap()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    // Reject ordinary FIFO/device inputs before a potentially blocking file open.
    if let Some(path) = args.iso.as_deref()
        && !tokio::fs::metadata(path).await?.is_file()
    {
        return Err("ISO must be a regular file".into());
    }
    let iso = if args.eject {
        None
    } else {
        let iso =
            tokio::fs::File::open(args.iso.as_ref().expect("iso present when mounting")).await?;
        let metadata = iso.metadata().await?;
        let size = metadata.len();
        if !metadata.is_file()
            || size == 0
            || !size.is_multiple_of(2048)
            || size / 2048 > u32::MAX as u64
        {
            return Err("ISO must be a nonempty regular file, a multiple of 2048 bytes, and fit READ(10) addressing".into());
        }
        Some((iso, size))
    };
    let (stop_tx, mut shutdown) = watch::channel(false);
    let signal = tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                let _ = stop_tx.send(true);
            }
            Err(e) => {
                eprintln!("Ctrl-C handler failed: {e}");
                let _ = stop_tx.send(true);
            }
        }
    });
    let tokens = match args.token_pair {
        Some(pair) => {
            auth::validate_tokens(&pair[0], &pair[1])?;
            mint::Tokens {
                user: pair[0].clone(),
                pass: pair[1].clone(),
                port: 623,
            }
        }
        None => {
            eprintln!("Minting tokens once (no automatic login retries)...");
            tokio::select! {
                _ = shutdown.changed() => return Ok(()),
                result = mint::mint(&args.host, args.user.as_deref().unwrap(), args.pass.as_deref().unwrap()) => result?,
            }
        }
    };
    let port = args.port.unwrap_or(tokens.port);
    if args.eject {
        eject(&host, port, args.slot, &tokens).await?;
        signal.abort();
        return Ok(());
    }
    let (mut iso, size) = iso.expect("ISO opened when not ejecting");
    let mut reconnecting = false;
    loop {
        if *shutdown.borrow() {
            break;
        }
        // Query before every mount, including reconnects: never take over an occupied slot.
        let probe = tokio::select! {
            _ = shutdown.changed() => break,
            result = proto::probe(&host, port, args.slot) => result,
        };
        if let Err(error) = probe {
            if !reconnecting || !is_transport_failure(error.as_ref()) {
                return Err(error);
            }
            eprintln!("Reconnect probe transport failed: {error}; retrying in 3s");
            if pause_or_stop(&mut shutdown).await {
                break;
            }
            continue;
        }
        if *shutdown.borrow() {
            break;
        }
        let connection = tokio::select! {
            _ = shutdown.changed() => break,
            result = timeout(IO_TIMEOUT, TcpStream::connect((host.as_str(), port))) => result,
        };
        let mut stream = match connection {
            Ok(Ok(stream)) => stream,
            outcome => {
                let error: Box<dyn std::error::Error + Send + Sync> = match outcome {
                    Ok(Err(e)) => Box::new(e),
                    Err(e) => Box::new(e),
                    _ => unreachable!(),
                };
                if !reconnecting {
                    return Err(error);
                }
                eprintln!(
                    "Reconnect transport failed: {error}; retrying in 3s with the same tokens"
                );
                if pause_or_stop(&mut shutdown).await {
                    break;
                }
                continue;
            }
        };
        if *shutdown.borrow() {
            break;
        }
        stream.set_nodelay(true)?;
        let auth = auth::build(&tokens.user, &tokens.pass, auth::nonce()?, args.slot)?;
        timeout(IO_TIMEOUT, stream.write_all(&auth))
            .await
            .map_err(|e| format!("vUSB auth send timed out: {e}"))?
            .map_err(|e| format!("vUSB auth send failed: {e}"))?;
        // Any auth/mount failure is fatal, including during reconnect: never try variations.
        timeout(IO_TIMEOUT, proto::authenticate(&mut stream))
            .await
            .map_err(|e| format!("vUSB auth acknowledgement timed out: {e}"))?
            .map_err(|e| format!("vUSB authentication failed: {e}"))?;
        if *shutdown.borrow() {
            timeout(IO_TIMEOUT, proto::unmount(&mut stream, args.slot)).await??;
            break;
        }
        proto::mount(&mut stream, args.slot)
            .await
            .map_err(|e| format!("vUSB mount setup send failed (closing session): {e}"))?;
        eprintln!(
            "Mount setup sent for {} ({} sectors) on {host}:{port}, slot {}; Ctrl-C to unmount",
            args.iso
                .as_ref()
                .expect("iso present when mounting")
                .display(),
            size / 2048,
            args.slot
        );
        match proto::serve(&mut stream, &mut iso, size, args.slot, &mut shutdown).await {
            Ok(()) => {
                eprintln!("Unmounting...");
                timeout(IO_TIMEOUT, proto::unmount(&mut stream, args.slot)).await??;
                eprintln!("Unmount sent; disconnected (remote release not yet confirmed).");
                break;
            }
            Err(error) if is_disconnect(error.as_ref()) => {
                eprintln!("TCP session dropped: {error}; reconnecting with the same tokens");
                reconnecting = true;
                if pause_or_stop(&mut shutdown).await {
                    break;
                }
            }
            // A failed outbound write may be partial: do not append an unmount to a
            // corrupt frame. Closing our TCP session also detaches the media.
            Err(error) => return Err(error),
        }
    }
    signal.abort();
    Ok(())
}

async fn eject(host: &str, port: u16, slot: u8, tokens: &mint::Tokens) -> Result<()> {
    let connection = timeout(IO_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| "vUSB connect timed out during eject")??;
    let mut stream = connection;
    stream.set_nodelay(true)?;
    let auth = auth::build(&tokens.user, &tokens.pass, auth::nonce()?, slot)?;
    stream
        .write_all(&auth)
        .await
        .map_err(|e| format!("vUSB auth send failed: {e}"))?;
    proto::authenticate(&mut stream)
        .await
        .map_err(|e| format!("vUSB authentication failed: {e}"))?;
    proto::unmount(&mut stream, slot).await?;
    eprintln!("Eject sent for slot {slot} on {host}:{port}; disconnecting.");
    Ok(())
}

async fn pause_or_stop(shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        _ = shutdown.changed() => true,
        _ = sleep(Duration::from_secs(3)) => false,
    }
}

fn is_transport_failure(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    is_disconnect(error)
        || error.is::<tokio::time::error::Elapsed>()
        || error.downcast_ref::<io::Error>().is_some_and(|e| {
            matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
            )
        })
}

fn is_disconnect(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error.downcast_ref::<io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn requested_shutdown_skips_retry_delay() {
        let (_tx, mut rx) = watch::channel(true);
        assert!(
            timeout(Duration::from_millis(100), pause_or_stop(&mut rx))
                .await
                .unwrap()
        );
    }
    #[test]
    fn only_transport_errors_are_retryable() {
        assert!(is_disconnect(&io::Error::from(
            io::ErrorKind::UnexpectedEof
        )));
        assert!(is_transport_failure(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        assert!(!is_transport_failure(&io::Error::from(
            io::ErrorKind::InvalidData
        )));
        assert!(!is_disconnect(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }
    #[test]
    fn credentials_are_exclusive_and_ports_bounded() {
        let base = ["aten-vm", "--host", "127.0.0.1", "--iso", "x.iso"];
        assert!(Args::try_parse_from(base).is_err());
        assert!(Args::try_parse_from(base.into_iter().chain(["--token-pair", "a", "b"])).is_ok());
        assert!(
            Args::try_parse_from(base.into_iter().chain(["--user", "u", "--pass", "p"])).is_ok()
        );
        assert!(
            Args::try_parse_from(
                base.into_iter()
                    .chain(["--user", "u", "--pass", "p", "--port", "0"])
            )
            .is_err()
        );
        assert!(
            Args::try_parse_from(
                base.into_iter()
                    .chain(["--token-pair", "a", "b", "--user", "u"])
            )
            .is_err()
        );
    }
}
