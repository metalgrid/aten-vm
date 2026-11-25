//! WebSocket transport for the Insyde HTML5 virtual-media path (`/vm`).
//! Wire evidence: the BMC's own client scripts (novnc/include/nav_ui.js,
//! vstorage.js) fetched live from firmware 01.73.11; see PROTOCOL-API.md.
use crate::Result;
use futures_util::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::ready,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest},
};

type Inner = WebSocketStream<MaybeTlsStream<Wire>>;

/// The raw byte wire under the WebSocket: direct or through a SOCKS5 proxy.
pub enum Wire {
    Plain(tokio::net::TcpStream),
    Socks5(Socks5Stream<tokio::net::TcpStream>),
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Wire::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Wire::Socks5(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Wire::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Wire::Socks5(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Wire::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Wire::Socks5(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Wire::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Wire::Socks5(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A binary-frame WebSocket presented as an AsyncRead/AsyncWrite byte stream.
///
/// Reads concatenate received message payloads, because PDU boundaries never
/// align with WebSocket frames (the firmware client reassembles the same way).
/// Writes accumulate until flush and then go out as exactly one binary message,
/// so each PDU maps to one WebSocket message, matching the browser client.
pub struct WsStream {
    inner: Inner,
    input: Vec<u8>,
    input_used: usize,
    output: Vec<u8>,
    closed: bool,
}

fn wire_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, error.to_string())
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.input_used < this.input.len() {
            let n = (this.input.len() - this.input_used).min(buf.remaining());
            buf.put_slice(&this.input[this.input_used..this.input_used + n]);
            this.input_used += n;
            if this.input_used == this.input.len() {
                this.input.clear();
                this.input_used = 0;
            }
            return Poll::Ready(Ok(()));
        }
        this.input.clear();
        this.input_used = 0;
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        // Do not let a PDU sit in `output` while we block on the peer; the
        // protocol writes a full PDU and then waits for its response.
        ready!(ready_flush(&mut this.inner, &mut this.output, cx))?;
        loop {
            match Stream::poll_next(Pin::new(&mut this.inner), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(event)) => match event {
                    Ok(Message::Binary(data)) => {
                        if data.is_empty() {
                            continue;
                        }
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            this.input = data[n..].to_vec();
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Message::Close(_)) => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => continue,
                    Ok(Message::Text(_)) => {
                        return Poll::Ready(Err(wire_error(
                            "virtual-media WebSocket sent an unexpected text frame",
                        )));
                    }
                    Err(e) => return Poll::Ready(Err(wire_error(e))),
                },
            }
        }
    }
}

fn ready_flush(
    inner: &mut Inner,
    output: &mut Vec<u8>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if !output.is_empty() {
        let pending = std::mem::take(output);
        if let Err(e) =
            <Inner as Sink<Message>>::start_send(Pin::new(inner), Message::Binary(pending.into()))
        {
            return Poll::Ready(Err(wire_error(e)));
        }
        return match <Inner as Sink<Message>>::poll_flush(Pin::new(inner), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(wire_error(e))),
            // start_send queued the message, so dropping the future cannot
            // lose it; the wake completes the flush on the next poll.
            Poll::Pending => Poll::Pending,
        };
    }
    Poll::Ready(Ok(()))
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready_flush(&mut this.inner, &mut this.output, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            ready!(ready_flush(&mut this.inner, &mut this.output, cx))?;
            match <Inner as Sink<Message>>::poll_close(Pin::new(&mut this.inner), cx) {
                Poll::Ready(Ok(())) => this.closed = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(wire_error(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Parse `socks5://host:port`; the only proxy type this tool supports.
pub fn parse_proxy(proxy: &str) -> Result<(String, u16)> {
    let rest = proxy
        .strip_prefix("socks5://")
        .ok_or("--proxy must be socks5://host:port")?;
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or("--proxy must be socks5://host:port")?;
    let port: u16 = port.parse().map_err(|_| "--proxy port must be 1..=65535")?;
    if port == 0 || host.is_empty() {
        return Err("--proxy must be socks5://host:port".into());
    }
    Ok((host.to_owned(), port))
}

async fn wire(host: &str, port: u16, proxy: Option<&(String, u16)>) -> Result<Wire> {
    let target = (host, port);
    Ok(match proxy {
        None => Wire::Plain(tokio::net::TcpStream::connect(target).await?),
        Some((proxy_host, proxy_port)) => {
            let proxy = format!("{proxy_host}:{proxy_port}");
            let stream = if proxy_host.parse::<std::net::IpAddr>().is_ok() {
                Socks5Stream::connect((proxy_host.as_str(), *proxy_port), target).await?
            } else {
                // Resolve the proxy name locally; the BMC address is passed through.
                Socks5Stream::connect(proxy.as_str(), target).await?
            };
            stream.set_nodelay(true)?;
            Wire::Socks5(stream)
        }
    })
}

/// Open the HTML5 virtual-media WebSocket (wss://host:port/vm) with the
/// session cookie. The BMC's certificate is self-signed; like the web minting
/// path, certificate verification is deliberately disabled.
pub async fn connect(
    host: &str,
    port: u16,
    sid: &str,
    proxy: Option<&(String, u16)>,
) -> Result<WsStream> {
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut request = format!("wss://{authority}/vm").into_client_request()?;
    let headers = request.headers_mut();
    headers.insert(
        "Cookie",
        format!("langSetFlag=0; language=English; SID={sid}").parse()?,
    );
    headers.insert("Origin", format!("https://{authority}").parse()?);
    let stream = wire(host, port, proxy).await?;
    let config = dangerous_rustls_config()?;
    let (ws, _response) = tokio_tungstenite::client_async_tls_with_config(
        request,
        stream,
        None,
        Some(Connector::Rustls(std::sync::Arc::new(config))),
    )
    .await
    .map_err(|e| format!("virtual-media WebSocket connect failed: {e}"))?;
    Ok(WsStream {
        inner: ws,
        input: Vec::new(),
        input_used: 0,
        output: Vec::new(),
        closed: false,
    })
}

/// rustls client config whose verification accepts any certificate, mirroring
/// `mint`'s danger_accept_invalid_certs for the BMC's self-signed key.
fn dangerous_rustls_config() -> Result<rustls::ClientConfig> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;

    #[derive(Debug)]
    struct AcceptAny(rustls::crypto::WebPkiSupportedAlgorithms);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }

    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny(algorithms)))
        .with_no_client_auth();
    config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    Ok(config)
}
