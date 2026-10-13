//! Direct embedded-Arti WebSocket transport. No local DNS or SOCKS listener is
//! involved in onion connections. ClearNet uses the SDK's default transport.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{BootstrapBehavior, TorClient};
use async_wsocket::Message;
use futures::future::BoxFuture;
use futures::{Sink, StreamExt};
use nostr_sdk::error::Error;
use nostr_sdk::prelude::{RelayUrl, Url};
use nostr_sdk::transport::websocket::{
    DefaultWebsocketTransport, WebSocketSink, WebSocketStream, WebSocketTransport,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OnceCell, watch};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
use tokio_tungstenite::{Connector, client_async_tls_with_config};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tor_rtcompat::tokio::TokioRustlsRuntime;

use crate::config::RelayConfig;

#[derive(Debug, PartialEq, Eq)]
enum Route {
    Direct,
    Tor,
}

fn route_url(url: &Url, onions: &BTreeSet<RelayUrl>) -> Result<Route, ()> {
    let relay = RelayUrl::parse(url.as_str()).map_err(|_| ())?;
    if !relay.is_onion() {
        return Ok(Route::Direct);
    }
    if onions.contains(&relay) {
        Ok(Route::Tor)
    } else {
        Err(())
    }
}

// Never retain arbitrary upstream errors: they can embed destination identities.
fn transport_error(reason: &'static str) -> Error {
    Error::transport(io::Error::other(reason))
}

trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}
type TorStream = Box<dyn IoStream>;

trait TorConnector: fmt::Debug + Send + Sync {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<TorStream, Error>>;
}

struct ArtiRuntime {
    client: Arc<TorClient<TokioRustlsRuntime>>,
    ready: watch::Receiver<bool>,
    // Abort bootstrap on final drop as well as explicit server shutdown.
    _bootstrap: AbortOnDropHandle<()>,
}

struct ArtiConnector {
    data_dir: String,
    runtime: OnceCell<ArtiRuntime>,
    shutdown: CancellationToken,
}

impl fmt::Debug for ArtiConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtiConnector").finish_non_exhaustive()
    }
}

impl ArtiConnector {
    async fn runtime(&self) -> Result<&ArtiRuntime, Error> {
        self.runtime
            .get_or_try_init(|| async {
                if self.shutdown.is_cancelled() {
                    return Err(transport_error("Tor transport is shutting down"));
                }
                let _ = rustls::crypto::ring::default_provider().install_default();
                let mut config = TorClientConfigBuilder::default();
                config.address_filter().allow_onion_addrs(true);
                if !self.data_dir.is_empty() {
                    let root = PathBuf::from(&self.data_dir);
                    config
                        .storage()
                        .cache_dir(CfgPath::new_literal(root.join("cache")))
                        .state_dir(CfgPath::new_literal(root.join("state")));
                }
                let config = config
                    .build()
                    .map_err(|_| transport_error("Invalid Tor configuration"))?;
                let runtime = TokioRustlsRuntime::current()
                    .map_err(|_| transport_error("Tor runtime initialization failed"))?;
                let client = TorClient::with_runtime(runtime)
                    .config(config)
                    .bootstrap_behavior(BootstrapBehavior::Manual)
                    .create_unbootstrapped_async()
                    .await
                    .map_err(|_| transport_error("Tor state initialization failed"))?;
                let bootstrap_client = client.clone();
                let shutdown = self.shutdown.clone();
                let (ready_tx, ready) = watch::channel(false);
                let bootstrap = tokio::spawn(bootstrap_until_ready(
                    move || {
                        let client = bootstrap_client.clone();
                        async move {
                            client
                                .bootstrap()
                                .await
                                .map_err(|_| transport_error("Tor bootstrap failed"))
                        }
                    },
                    shutdown,
                    ready_tx,
                    Duration::from_secs(5),
                ));
                Ok(ArtiRuntime {
                    client,
                    ready,
                    _bootstrap: AbortOnDropHandle::new(bootstrap),
                })
            })
            .await
    }
}

// Keep bootstrap outside the SDK dial future, so a handshake deadline cannot
// cancel shared initialization. Only successful bootstrap releases waiters.
async fn bootstrap_until_ready<F, Fut>(
    mut attempt: F,
    shutdown: CancellationToken,
    ready: watch::Sender<bool>,
    retry_interval: Duration,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), Error>>,
{
    loop {
        let result = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            result = attempt() => result,
        };
        if result.is_ok() {
            ready.send_replace(true);
            return;
        }
        tracing::debug!("Tor bootstrap failed; retrying");
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(retry_interval) => {}
        }
    }
}

async fn wait_for_bootstrap(mut ready: watch::Receiver<bool>) -> Result<(), Error> {
    ready
        .wait_for(|value| *value)
        .await
        .map(|_| ())
        .map_err(|_| transport_error("Tor bootstrap stopped"))
}

impl TorConnector for ArtiConnector {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<TorStream, Error>> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => Err(transport_error("Tor transport is shutting down")),
                result = async {
                    let runtime = self.runtime().await?;
                    wait_for_bootstrap(runtime.ready.clone()).await?;
                    let stream = runtime.client.connect((host, port)).await
                        .map_err(|_| transport_error("Tor connection failed"))?;
                    Ok(Box::new(stream) as TorStream)
                } => result,
            }
        })
    }
}

/// Routes configured onions through one lazily initialized embedded Arti client.
pub(super) struct TorTransport {
    onions: BTreeSet<RelayUrl>,
    connector: Arc<dyn TorConnector>,
    shutdown: CancellationToken,
}

impl fmt::Debug for TorTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorTransport")
            .field("onion_count", &self.onions.len())
            .finish()
    }
}

impl TorTransport {
    /// Create a transport without starting Arti or touching its state directories.
    pub(super) fn new(config: &RelayConfig) -> Result<Self, Error> {
        let onions = config
            .onion
            .iter()
            .map(|url| RelayUrl::parse(url))
            .collect::<Result<_, _>>()
            .map_err(|_| transport_error("Invalid configured onion relay"))?;
        let shutdown = CancellationToken::new();
        let connector = Arc::new(ArtiConnector {
            data_dir: config.tor_data_dir.clone(),
            runtime: OnceCell::new(),
            shutdown: shutdown.clone(),
        });
        Ok(Self {
            onions,
            connector,
            shutdown,
        })
    }

    /// Cancel bootstrap retries and pending onion dials during server shutdown.
    pub(super) fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

impl WebSocketTransport for TorTransport {
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        proxy: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
        Box::pin(async move {
            match route_url(url, &self.onions)
                .map_err(|_| transport_error("Unconfigured onion relay"))?
            {
                Route::Direct => return DefaultWebsocketTransport.connect(url, proxy).await,
                Route::Tor => {}
            }
            if proxy.is_some() {
                return Err(transport_error(
                    "A proxy cannot override embedded Tor routing",
                ));
            }
            let host = url
                .host_str()
                .ok_or_else(|| transport_error("Missing onion host"))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| transport_error("Missing onion port"))?;
            // Passing the hostname to Arti is essential: never resolve it locally.
            let stream = self.connector.connect(host, port).await?;
            let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| transport_error("Tor WebSocket TLS configuration failed"))?
            .with_root_certificates(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
            .with_no_client_auth();
            let mut request = url
                .as_str()
                .into_client_request()
                .map_err(|_| transport_error("Invalid onion WebSocket request"))?;
            request.headers_mut().insert(
                "user-agent",
                "nostr-sdk/0.45.4"
                    .parse()
                    .map_err(|_| transport_error("Invalid WebSocket user agent"))?,
            );
            let (socket, _) = client_async_tls_with_config(
                request,
                stream,
                None,
                Some(Connector::Rustls(Arc::new(tls_config))),
            )
            .await
            .map_err(|_| transport_error("Onion WebSocket handshake failed"))?;
            let (tx, rx) = socket.split();
            let tx: WebSocketSink = Box::pin(MessageSink(tx));
            let rx: WebSocketStream = Box::pin(rx.map(|message| {
                message
                    .map_err(|_| transport_error("Onion WebSocket receive failed"))
                    .and_then(from_native_message)
            }));
            Ok((tx, rx))
        })
    }
}

fn from_native_message(message: tungstenite::Message) -> Result<Message, Error> {
    Ok(match message {
        tungstenite::Message::Text(text) => Message::Text(text.to_string()),
        tungstenite::Message::Binary(bytes) => Message::Binary(bytes.to_vec()),
        tungstenite::Message::Ping(bytes) => Message::Ping(bytes.to_vec()),
        tungstenite::Message::Pong(bytes) => Message::Pong(bytes.to_vec()),
        tungstenite::Message::Close(frame) => Message::Close(frame.map(Into::into)),
        tungstenite::Message::Frame(_) => {
            return Err(transport_error("Unexpected raw WebSocket frame"));
        }
    })
}

// Avoid SinkExt::sink_map_err: SDK upstream documents a panic in that adapter.
struct MessageSink<S>(S);
impl<S: Sink<tungstenite::Message> + Unpin + Send> Sink<Message> for MessageSink<S> {
    type Error = Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0)
            .poll_ready(cx)
            .map_err(|_| transport_error("Onion WebSocket send failed"))
    }
    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Error> {
        Pin::new(&mut self.0)
            .start_send(item.into())
            .map_err(|_| transport_error("Onion WebSocket send failed"))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(|_| transport_error("Onion WebSocket flush failed"))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(|_| transport_error("Onion WebSocket close failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::SinkExt;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, DuplexStream};

    #[derive(Debug)]
    struct FakeConnector {
        stream: Mutex<Option<DuplexStream>>,
        calls: AtomicUsize,
        target: Mutex<Option<(String, u16)>>,
    }

    impl TorConnector for FakeConnector {
        fn connect<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFuture<'a, Result<TorStream, Error>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                *self.target.lock().unwrap() = Some((host.to_owned(), port));
                self.stream
                    .lock()
                    .unwrap()
                    .take()
                    .map(|stream| Box::new(stream) as TorStream)
                    .ok_or_else(|| transport_error("Tor connection failed"))
            })
        }
    }

    fn fake_transport(
        url: &Url,
        stream: Option<DuplexStream>,
    ) -> (TorTransport, Arc<FakeConnector>) {
        let connector = Arc::new(FakeConnector {
            stream: Mutex::new(stream),
            calls: AtomicUsize::new(0),
            target: Mutex::new(None),
        });
        let transport = TorTransport {
            onions: BTreeSet::from([RelayUrl::parse(url.as_str()).unwrap()]),
            connector: connector.clone(),
            shutdown: CancellationToken::new(),
        };
        (transport, connector)
    }

    #[test]
    fn configured_onions_use_tor() {
        let relay = RelayUrl::parse("ws://example.onion:8080").unwrap();
        let onions = BTreeSet::from([relay]);
        let url = Url::parse("ws://example.onion:8080").unwrap();
        assert_eq!(route_url(&url, &onions), Ok(Route::Tor));
    }

    #[test]
    fn unconfigured_onion_fails_closed() {
        let url = Url::parse("ws://unexpected.onion").unwrap();
        assert!(route_url(&url, &BTreeSet::new()).is_err());
    }

    #[test]
    fn onion_text_in_clearnet_path_is_not_tor() {
        let url = Url::parse("wss://relay.example/path.onion").unwrap();
        assert_eq!(route_url(&url, &BTreeSet::new()), Ok(Route::Direct));
    }

    #[tokio::test]
    async fn onion_websocket_preserves_data_ping_pong_and_close() {
        let url = Url::parse("ws://example.onion:8080/path").unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (transport, connector) = fake_transport(&url, Some(client_io));
        let server = tokio::spawn(async move {
            let mut socket = tokio_tungstenite::accept_async(server_io).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                tungstenite::Message::Text("request".into())
            );
            socket
                .send(tungstenite::Message::Binary(vec![1, 2, 3].into()))
                .await
                .unwrap();
            socket
                .send(tungstenite::Message::Ping(vec![4].into()))
                .await
                .unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                tungstenite::Message::Pong(vec![4].into())
            );
            socket.close(None).await.unwrap();
        });
        let (mut tx, mut rx) = transport.connect(&url, None).await.unwrap();
        assert_eq!(
            connector.target.lock().unwrap().as_ref(),
            Some(&("example.onion".into(), 8080))
        );
        tx.send(Message::Text("request".into())).await.unwrap();
        assert_eq!(
            rx.next().await.unwrap().unwrap(),
            Message::Binary(vec![1, 2, 3])
        );
        assert_eq!(rx.next().await.unwrap().unwrap(), Message::Ping(vec![4]));
        tx.send(Message::Pong(vec![4])).await.unwrap();
        assert!(matches!(
            rx.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_onion_dial_never_falls_back_to_direct() {
        let url = Url::parse("ws://example.onion").unwrap();
        let (transport, connector) = fake_transport(&url, None);
        let error = transport
            .connect(&url, None)
            .await
            .err()
            .expect("failed Tor dial unexpectedly connected");
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(error.to_string(), "Tor connection failed");
        assert!(!format!("{transport:?}").contains("example.onion"));
    }

    #[tokio::test]
    async fn onion_proxy_override_is_rejected_before_dial() {
        let url = Url::parse("ws://example.onion").unwrap();
        let (transport, connector) = fake_transport(&url, None);
        assert!(
            transport
                .connect(&url, Some("127.0.0.1:9050".parse().unwrap()))
                .await
                .is_err()
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wss_requires_tls_over_the_tor_stream() {
        let url = Url::parse("wss://example.onion").unwrap();
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let (transport, _) = fake_transport(&url, Some(client_io));
        let server = tokio::spawn(async move {
            let mut first = [0; 3];
            server_io.read_exact(&mut first).await.unwrap();
            // TLS handshake record, not a cleartext HTTP GET.
            assert_eq!(first[0], 0x16);
            assert_eq!(first[1], 0x03);
        });
        assert!(transport.connect(&url, None).await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn clearnet_delegates_without_using_arti() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
        let (transport, connector) = fake_transport(&url, None);
        let server = tokio::spawn(async move {
            let (io, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(io).await.unwrap();
            socket
                .send(tungstenite::Message::Text("direct".into()))
                .await
                .unwrap();
        });
        let (_, mut rx) = transport.connect(&url, None).await.unwrap();
        assert_eq!(
            rx.next().await.unwrap().unwrap(),
            Message::Text("direct".into())
        );
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_prevents_arti_initialization() {
        let connector = ArtiConnector {
            data_dir: String::new(),
            runtime: OnceCell::new(),
            shutdown: CancellationToken::new(),
        };
        connector.shutdown.cancel();
        assert!(connector.connect("example.onion", 80).await.is_err());
        assert!(connector.runtime.get().is_none());
    }

    #[tokio::test]
    async fn first_dial_waits_for_bootstrap_and_shutdown_cancels_it() {
        let data = tempfile::tempdir().unwrap();
        let connector = ArtiConnector {
            data_dir: data.path().to_string_lossy().into_owned(),
            runtime: OnceCell::new(),
            shutdown: CancellationToken::new(),
        };
        connector.runtime().await.unwrap();
        // Poll the first dial before the spawned bootstrap task can run.
        // No network is needed: it must wait for readiness, not immediately
        // return BootstrapRequired from Arti's manual-bootstrap mode.
        let mut dial = Box::pin(connector.connect("example.onion", 80));
        assert!(
            futures::poll!(dial.as_mut()).is_pending(),
            "first onion dial must wait for bootstrap readiness"
        );
        connector.shutdown.cancel();
        assert!(dial.await.is_err());
        assert!(data.path().join("cache").is_dir());
        assert!(data.path().join("state").is_dir());
    }

    #[tokio::test]
    async fn bootstrap_retries_failures_then_releases_all_waiters() {
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(bootstrap_until_ready(
            move || {
                let number = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if number == 0 {
                        Err(transport_error("bootstrap failed"))
                    } else {
                        Ok(())
                    }
                }
            },
            CancellationToken::new(),
            tx,
            Duration::from_millis(1),
        ));
        let (first, second) = tokio::join!(wait_for_bootstrap(rx.clone()), wait_for_bootstrap(rx));
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn dial_deadline_does_not_cancel_shared_bootstrap() {
        let complete = Arc::new(tokio::sync::Notify::new());
        let pending = complete.clone();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(bootstrap_until_ready(
            move || {
                let pending = pending.clone();
                async move {
                    pending.notified().await;
                    Ok(())
                }
            },
            CancellationToken::new(),
            tx,
            Duration::from_millis(1),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait_for_bootstrap(rx.clone()))
                .await
                .is_err()
        );
        assert!(!task.is_finished());
        complete.notify_one();
        assert!(wait_for_bootstrap(rx).await.is_ok());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_cancels_bootstrap_in_progress() {
        let started = Arc::new(tokio::sync::Notify::new());
        let attempt_started = started.clone();
        let shutdown = CancellationToken::new();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(bootstrap_until_ready(
            move || {
                attempt_started.notify_one();
                futures::future::pending::<Result<(), Error>>()
            },
            shutdown.clone(),
            tx,
            Duration::from_secs(5),
        ));
        started.notified().await;
        shutdown.cancel();
        task.await.unwrap();
        assert!(wait_for_bootstrap(rx).await.is_err());
    }

    #[tokio::test]
    async fn shutdown_cancels_bootstrap_retry_backoff() {
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let attempt_started = started.clone();
        let shutdown = CancellationToken::new();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(bootstrap_until_ready(
            move || {
                attempts.fetch_add(1, Ordering::SeqCst);
                attempt_started.notify_one();
                futures::future::ready(Err(transport_error("bootstrap failed")))
            },
            shutdown.clone(),
            tx,
            Duration::from_secs(60),
        ));
        started.notified().await;
        shutdown.cancel();
        task.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!*rx.borrow());
    }

    #[tokio::test]
    async fn arti_initialization_failure_is_redacted_and_can_retry() {
        let data = tempfile::tempdir().unwrap();
        let root = data.path().join("arti");
        std::fs::write(&root, b"not a directory").unwrap();
        let connector = ArtiConnector {
            data_dir: root.to_string_lossy().into_owned(),
            runtime: OnceCell::new(),
            shutdown: CancellationToken::new(),
        };
        assert!(!format!("{connector:?}").contains(connector.data_dir.as_str()));
        assert!(connector.runtime().await.is_err());
        assert!(connector.runtime.get().is_none());
        std::fs::remove_file(&root).unwrap();
        let runtime = connector.runtime().await.unwrap();
        let again = connector.runtime().await.unwrap();
        assert!(Arc::ptr_eq(&runtime.client, &again.client));
        connector.shutdown.cancel();
        assert!(root.join("cache").is_dir() && root.join("state").is_dir());
    }

    #[tokio::test]
    async fn cancelled_runtime_cannot_start_bootstrap() {
        let connector = ArtiConnector {
            data_dir: String::new(),
            runtime: OnceCell::new(),
            shutdown: CancellationToken::new(),
        };
        connector.shutdown.cancel();
        assert!(connector.runtime().await.is_err());
        assert!(connector.runtime.get().is_none());
    }

    #[tokio::test]
    // Tungstenite fixes the callback error type to a full HTTP response.
    #[allow(clippy::result_large_err)]
    async fn websocket_close_flushes_the_tor_stream() {
        let url = Url::parse("ws://example.onion").unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (transport, _) = fake_transport(&url, Some(client_io));
        let server = tokio::spawn(async move {
            let mut socket = tokio_tungstenite::accept_hdr_async(
                server_io,
                |request: &tungstenite::handshake::server::Request, response| {
                    assert_eq!(request.headers()["user-agent"], "nostr-sdk/0.45.4");
                    Ok(response)
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                socket.next().await.unwrap().unwrap(),
                tungstenite::Message::Close(_)
            ));
        });
        assert!(transport.support_ping());
        let (mut tx, _) = transport.connect(&url, None).await.unwrap();
        tx.close().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn inbound_websocket_messages_preserve_text_pong_and_close_reason() {
        assert_eq!(
            from_native_message(tungstenite::Message::Text("event".into())).unwrap(),
            Message::Text("event".into())
        );
        assert_eq!(
            from_native_message(tungstenite::Message::Pong(vec![1].into())).unwrap(),
            Message::Pong(vec![1])
        );
        let close = tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "done".into(),
        };
        assert_eq!(
            from_native_message(tungstenite::Message::Close(Some(close))).unwrap(),
            Message::Close(Some(async_wsocket::message::CloseFrame {
                code: 1000,
                reason: "done".into()
            }))
        );
    }

    #[tokio::test]
    async fn unknown_onion_is_rejected_before_any_dial() {
        let configured = Url::parse("ws://example.onion").unwrap();
        let (transport, connector) = fake_transport(&configured, None);
        let unexpected = Url::parse("ws://unexpected.onion").unwrap();
        assert!(transport.connect(&unexpected, None).await.is_err());
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn raw_frames_are_rejected_without_panicking() {
        let frame = tungstenite::protocol::frame::Frame::message(
            Vec::<u8>::new(),
            tungstenite::protocol::frame::coding::OpCode::Data(
                tungstenite::protocol::frame::coding::Data::Binary,
            ),
            true,
        );
        assert!(from_native_message(tungstenite::Message::Frame(frame)).is_err());
    }

    #[test]
    fn invalid_relay_schemes_are_rejected() {
        let url = Url::parse("https://example.onion").unwrap();
        assert!(route_url(&url, &BTreeSet::new()).is_err());
        let config: RelayConfig = serde_json::from_value(serde_json::json!({
            "onion": ["not a relay URL"],
        }))
        .unwrap();
        assert!(TorTransport::new(&config).is_err());
    }

    struct FailingSink;
    impl Sink<tungstenite::Message> for FailingSink {
        type Error = io::Error;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Err(io::Error::other("sensitive destination.onion")))
        }
        fn start_send(self: Pin<&mut Self>, _: tungstenite::Message) -> Result<(), io::Error> {
            Err(io::Error::other("sensitive destination.onion"))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Err(io::Error::other("sensitive destination.onion")))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Err(io::Error::other("sensitive destination.onion")))
        }
    }

    #[tokio::test]
    async fn sink_errors_never_expose_upstream_destinations() {
        let mut sink = MessageSink(FailingSink);
        let messages = [
            futures::future::poll_fn(|cx| Pin::new(&mut sink).poll_ready(cx))
                .await
                .unwrap_err()
                .to_string(),
            Pin::new(&mut sink)
                .start_send(Message::Text("event".into()))
                .unwrap_err()
                .to_string(),
            futures::future::poll_fn(|cx| Pin::new(&mut sink).poll_flush(cx))
                .await
                .unwrap_err()
                .to_string(),
            futures::future::poll_fn(|cx| Pin::new(&mut sink).poll_close(cx))
                .await
                .unwrap_err()
                .to_string(),
        ];
        assert!(
            messages
                .iter()
                .all(|message| !message.contains("destination.onion"))
        );
    }

    #[tokio::test]
    async fn real_bootstrap_task_stops_without_waiting_for_network_success() {
        let data = tempfile::tempdir().unwrap();
        let mut connector = ArtiConnector {
            data_dir: data.path().to_string_lossy().into_owned(),
            runtime: OnceCell::new(),
            shutdown: CancellationToken::new(),
        };
        connector.runtime().await.unwrap();
        // Exercise the real bootstrap future, then cancel it. This works with
        // Tor unreachable and never requires a directory download to succeed.
        tokio::task::yield_now().await;
        assert!(!connector.runtime.get().unwrap()._bootstrap.is_finished());
        connector.shutdown.cancel();
        let runtime = connector.runtime.take().unwrap();
        tokio::time::timeout(Duration::from_secs(1), runtime._bootstrap)
            .await
            .unwrap()
            .unwrap();
        assert!(!*runtime.ready.borrow());
    }
}
