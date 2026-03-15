use crate::error::{Error, Result};
use crate::protocol::{AuthRequest, AuthResponse, DaemonResponse, ErrorResponse};
use crate::traits::RequestHandler;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Listens on a Unix socket and dispatches auth requests.
///
/// Resilient: individual connection errors are logged, not propagated.
/// The daemon only terminates on bind failure or explicit shutdown.
pub async fn serve(
    socket_path: &Path,
    handler: &dyn RequestHandler,
) -> Result<()> {
    // Clean up stale socket.
    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    eprintln!(
        "[akeyless-auth] listening on {}",
        socket_path.display()
    );

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[akeyless-auth] accept error (continuing): {e}");
                continue;
            }
        };

        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        if let Err(e) = buf_reader.read_line(&mut line).await {
            eprintln!("[akeyless-auth] read error (continuing): {e}");
            continue;
        }

        if line.is_empty() {
            continue;
        }

        let response_json = match serde_json::from_str::<AuthRequest>(&line) {
            Ok(req) => match handler.handle(&req) {
                Ok(resp) => serde_json::to_string(&resp).unwrap_or_else(|e| {
                    serde_json::to_string(&ErrorResponse {
                        error: format!("serialization error: {e}"),
                    })
                    .unwrap()
                }),
                Err(e) => serde_json::to_string(&ErrorResponse {
                    error: e.to_string(),
                })
                .unwrap(),
            },
            Err(e) => serde_json::to_string(&ErrorResponse {
                error: format!("invalid request: {e}"),
            })
            .unwrap(),
        };

        let _ = writer.write_all(response_json.as_bytes()).await;
        let _ = writer.write_all(b"\n").await;
    }
}

/// Request a token from the daemon via Unix socket.
///
/// Handles both success (`AuthResponse`) and error (`ErrorResponse`) from daemon.
pub async fn request_token(socket_path: &Path, req: &AuthRequest) -> Result<AuthResponse> {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        Error::Socket(std::io::Error::new(
            e.kind(),
            format!(
                "failed to connect to akeyless-auth daemon at {}: {e}",
                socket_path.display()
            ),
        ))
    })?;

    let (reader, mut writer) = stream.into_split();

    let request_json = serde_json::to_string(req)?;
    writer.write_all(request_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;

    // Try parsing as DaemonResponse (untagged: success or error).
    let daemon_resp: DaemonResponse = serde_json::from_str(&response_line).map_err(|e| {
        Error::Config(format!("invalid response from daemon: {e}: {response_line}"))
    })?;

    match daemon_resp {
        DaemonResponse::Ok(auth) => Ok(auth),
        DaemonResponse::Err(err) => Err(Error::Daemon(err.error)),
    }
}
