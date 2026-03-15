use crate::error::{Error, Result};
use crate::protocol::{AuthRequest, AuthResponse};
use crate::traits::RequestHandler;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Listens on a Unix socket and dispatches auth requests.
pub async fn serve(
    socket_path: &Path,
    handler: &dyn RequestHandler,
) -> Result<()> {
    // Clean up stale socket.
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|e| {
            Error::Socket(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to remove stale socket: {e}"),
            ))
        })?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    eprintln!(
        "[akeyless-auth] listening on {}",
        socket_path.display()
    );

    loop {
        let (stream, _addr) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        let mut line = String::new();
        if buf_reader.read_line(&mut line).await? == 0 {
            continue; // empty connection
        }

        let response = match serde_json::from_str::<AuthRequest>(&line) {
            Ok(req) => match handler.handle(&req) {
                Ok(resp) => serde_json::to_string(&resp).unwrap_or_else(|e| {
                    format!("{{\"error\":\"{e}\"}}")
                }),
                Err(e) => format!("{{\"error\":\"{e}\"}}"),
            },
            Err(e) => format!("{{\"error\":\"invalid request: {e}\"}}"),
        };

        let _ = writer.write_all(response.as_bytes()).await;
        let _ = writer.write_all(b"\n").await;
    }
}

/// Request a token from the daemon via Unix socket.
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

    let mut buf_reader = BufReader::new(reader);
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;

    serde_json::from_str(&response_line).map_err(|e| {
        Error::Config(format!("invalid response from daemon: {e}: {response_line}"))
    })
}
