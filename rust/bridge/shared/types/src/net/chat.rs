//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use atomic_take::AtomicTake;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::{FutureExt as _, Stream, StreamExt as _};
use http::status::InvalidStatusCode;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_account_keys::{MEDIA_ENCRYPTION_KEY_LEN, MEDIA_ID_LEN};
use libsignal_bridge_macros::{BridgedAsValue, bridge_callbacks};
use libsignal_core::LogSafeDisplay;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::ws::ListenerEvent;
use libsignal_net::chat::{
    self, ChatConnection, ConnectError, ConnectionInfo, DebugInfo as ChatServiceDebugInfo,
    GrpcBody, LanguageList, Request, Response as ChatResponse, SendError,
    UnauthenticatedChatHeaders,
};
use libsignal_net::connect_state::ConnectionResources;
use libsignal_net::env::constants::{CHAT_PROVISIONING_PATH, CHAT_WEBSOCKET_PATH};
use libsignal_net::infra::http_client::Http2Client;
use libsignal_net::infra::route::{
    DirectOrProxyMode, DirectOrProxyModeDiscriminants, DirectOrProxyProvider, RouteProvider,
    RouteProviderExt, TcpRoute, TlsRoute, UnresolvedHttpsServiceRoute,
};
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::infra::ws::WebSocketError;
use libsignal_net::infra::{EnableDomainFronting, EnforceMinimumTls, OverrideNagleAlgorithm};
use libsignal_net_chat::api::backups::BackupAuthCredentialRejected;
use libsignal_net_chat::api::{Auth as AuthConn, RequestError, Unauth};
use libsignal_net_chat::grpc::GrpcServiceProvider;
use libsignal_net_chat::grpc::backups::{
    CopyBackupMediaFailure, CopyBackupMediaItem, CopyBackupMediaOutcome, DeleteBackupMediaItem,
    MediaBackupInfo, MessageBackupInfo,
};
use libsignal_net_chat::stream_util::{
    BulkPolledStream, BulkPolledStreamChunk, BulkPolledStreamTerminationReason,
};
use libsignal_net_chat::ws::WsConnection;
use libsignal_protocol::{IdentityKey, PreKeyBundle, Timestamp};
use static_assertions::assert_impl_all;

use crate::net::ConnectionManager;
use crate::net::remote_config::RemoteConfigKey;
use crate::support::{
    AsyncMutex, BridgeVec, BridgedError, LimitedLifetimeRef, ResultLike, WithContext,
};
use crate::*;

pub type ChatConnectionInfo = ConnectionInfo;

bridge_as_handle!(ChatConnectionInfo);

pub struct UnauthenticatedChatConnection {
    /// The possibly-still-being-constructed [`ChatConnection`].
    ///
    /// See [`AuthenticatedChatConnection::inner`] for rationale around lack of
    /// reader/writer contention.
    inner: tokio::sync::RwLock<MaybeChatConnection>,
}
bridge_as_handle!(
    UnauthenticatedChatConnection,
    swift_type = "UnauthenticatedChatConnection",
    jni_class = "org.signal.libsignal.net.UnauthenticatedChatConnection",
);
impl UnwindSafe for UnauthenticatedChatConnection {}
impl RefUnwindSafe for UnauthenticatedChatConnection {}

pub struct AuthenticatedChatConnection {
    /// The possibly-still-being-constructed [`ChatConnection`].
    ///
    /// This is a `RwLock` so that bridging functions can always take a
    /// `&AuthenticatedChatConnection`, even when finishing construction of the
    /// `ChatConnection`. The lock will only be held in writer mode once, when
    /// finishing construction, and after that will be held in read mode, so
    /// there won't be any contention.
    inner: tokio::sync::RwLock<MaybeChatConnection>,
}
bridge_as_handle!(
    AuthenticatedChatConnection,
    swift_type = "AuthenticatedChatConnection",
    jni_class = "org.signal.libsignal.net.AuthenticatedChatConnection",
);
impl UnwindSafe for AuthenticatedChatConnection {}
impl RefUnwindSafe for AuthenticatedChatConnection {}

pub struct ProvisioningChatConnection {
    /// The possibly-still-being-constructed [`ChatConnection`].
    ///
    /// See [`AuthenticatedChatConnection::inner`] for rationale around lack of
    /// reader/writer contention.
    inner: tokio::sync::RwLock<MaybeChatConnection>,
}
bridge_as_handle!(ProvisioningChatConnection);
impl UnwindSafe for ProvisioningChatConnection {}
impl RefUnwindSafe for ProvisioningChatConnection {}

// We could Box the PendingChatConnection, but in practice this type will be on the heap anyway, and
// there won't be a ton of them allocated.
#[expect(clippy::large_enum_variant)]
enum MaybeChatConnection {
    Running(ChatWire),
    WaitingForListener {
        runtime: tokio::runtime::Handle,
        pending: AsyncMutex<chat::PendingChatConnection>,
        grpc_overrides: HashMap<&'static str, chat::GrpcOverride>,
    },
    TemporarilyEvicted,
}

assert_impl_all!(MaybeChatConnection: Send, Sync);

/// What a running connection sends on.
///
/// Every typed service in `libsignal-net-chat` is written against [`WsConnection`], whose whole
/// contract is "send this HTTP-shaped request and hand back the HTTP-shaped response". The
/// websocket is one way to keep that contract. A process that cannot hold a websocket -- a
/// watch, whose only egress is a reverse proxy -- keeps it with a [`ChatRequester`] instead,
/// and every service above the wire (messages, profiles, usernames, keys, key transparency)
/// runs over it unchanged: the same request builders, the same response decoders, the same
/// error mapping. The gRPC-backed calls are the exception. They need the websocket's HTTP/2
/// companion, which a requester cannot stand in for, so [`Self::shared_h2_connection`] is
/// `None` and `require_grpc` refuses them.
// `MaybeChatConnection`'s own reasoning applies: it lives on the heap anyway, and there are few.
#[expect(clippy::large_enum_variant)]
pub enum ChatWire {
    Ws(ChatConnection),
    Requester(RequesterConnection),
}

impl ChatWire {
    pub async fn send(&self, msg: Request, timeout: Duration) -> Result<ChatResponse, SendError> {
        match self {
            Self::Ws(connection) => connection.send(msg, timeout).await,
            Self::Requester(requester) => {
                let request_id = requester.allocate_request_id();
                requester.send_request(msg, request_id).await
            }
        }
    }

    pub async fn disconnect(&self) {
        match self {
            Self::Ws(connection) => connection.disconnect().await,
            Self::Requester(_) => {}
        }
    }

    /// `None` for a requester: there is no socket to describe.
    pub fn connection_info(&self) -> Option<&ConnectionInfo> {
        match self {
            Self::Ws(connection) => Some(connection.connection_info()),
            Self::Requester(_) => None,
        }
    }

    pub fn shared_h2_connection(&self) -> Option<Http2Client<GrpcBody>> {
        match self {
            Self::Ws(connection) => connection.shared_h2_connection(),
            Self::Requester(_) => None,
        }
    }
}

impl WsConnection for ChatWire {
    async fn send(
        &self,
        log_tag: &'static str,
        log_safe_path: &str,
        request: Request,
    ) -> Result<ChatResponse, SendError> {
        match self {
            Self::Ws(connection) => {
                WsConnection::send(connection, log_tag, log_safe_path, request).await
            }
            Self::Requester(requester) => {
                WsConnection::send(requester, log_tag, log_safe_path, request).await
            }
        }
    }

    fn grpc_service_to_use_instead(
        &self,
        message: &'static str,
    ) -> Option<impl GrpcServiceProvider> {
        match self {
            Self::Ws(connection) => connection.grpc_service_to_use_instead(message),
            Self::Requester(_) => None,
        }
    }

    fn self_aci(&self) -> Option<libsignal_core::Aci> {
        match self {
            Self::Ws(connection) => WsConnection::self_aci(connection),
            Self::Requester(requester) => requester.self_aci,
        }
    }
}

/// What a [`ChatRequester`] hands back: an HTTP response, complete and undecoded.
///
/// `headers` are `Name: value` lines, one per header, as HTTP itself writes them. The decoders
/// above the wire read `Content-Type` and `Retry-After` and expect the server's exact values
/// (a reply with no body must carry no content type at all), so a requester forwards every
/// header it received rather than choosing among them. `body` is empty for a response without
/// one. Built through `ChatRequesterResponse_New`.
pub struct ChatRequesterResponse {
    pub status: u16,
    pub headers: Box<[String]>,
    pub body: Vec<u8>,
}

bridge_as_handle!(ChatRequesterResponse);

/// The wire an app supplies for a chat connection that has no websocket.
///
/// `send` is one HTTP request at the chat server, made however the app likes, returning when
/// the reply is in hand. It is synchronous by contract and is invoked off libsignal's async
/// runtime, on a thread that exists to be blocked. `headers` are `Name: value` lines carrying
/// everything libsignal would have sent down the socket for this request (the unidentified
/// access key, the content type, ...); the app adds whatever its own transport needs. A
/// connection that is authenticated at the socket sends no `Authorization` per request, so a
/// requester standing in for an authenticated connection adds it. `body` is empty for a
/// request without one.
///
/// A thrown error means the request never reached the server or the reply never came back. It
/// is reported as a transport failure, which callers treat as retryable. A reply the server did
/// send -- whatever its status -- is a response, not an error, so that each service's own
/// status handling (rate limits, mismatched devices, rejections) applies to it.
///
/// `cancel` says that nobody is waiting for `request_id` any more: the caller's future was
/// dropped while that request was still in flight. It may arrive on any thread and at any point
/// in that request's life -- during its `send`, after `send` has returned (where it means
/// nothing and is to be ignored), and even before `send` is entered, because a blocking call
/// that is still queued when its handle is dropped is run anyway. It arrives at most once per
/// id, and only for an id that has been or will be passed to `send`.
///
/// A requester that ignores it altogether is still correct; it just holds the wire, and the
/// thread `send` is blocking, until the reply or its own timeout arrives. `send`'s return value
/// after a `cancel` is discarded, so it may return however it likes -- an error is the natural
/// one.
#[bridge_callbacks(jni = false, node = false)]
pub trait ChatRequester: Send + Sync + UnwindSafe {
    fn send(
        &self,
        request_id: u64,
        method: String,
        path: String,
        headers: Box<[String]>,
        body: Vec<u8>,
    ) -> Result<ChatRequesterResponse, std::io::Error>;

    fn cancel(&self, request_id: u64);
}

/// A chat connection whose wire is a [`ChatRequester`].
///
/// Shared by `Arc` because each request runs on tokio's blocking pool, and the blocking task
/// has to own what it calls.
pub struct RequesterConnection {
    requester: Arc<dyn ChatRequester>,
    self_aci: Option<libsignal_core::Aci>,
    next_request_id: AtomicU64,
}

/// Tells the requester to let go of a request nobody is waiting for any more.
///
/// [`RequesterConnection::send_request`] arms one of these around the blocking call and disarms
/// it the instant that call returns, so `Drop` runs with it still armed only when the future was
/// dropped mid-flight -- which is what a cancelled caller looks like from here, the bridged
/// future being `select!`ed against cancellation and dropped. It holds the requester by `Arc`
/// because the connection that owns it may be dropped in the same breath.
struct CancelOnDrop {
    requester: Arc<dyn ChatRequester>,
    request_id: u64,
    armed: bool,
}

impl CancelOnDrop {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.requester.cancel(self.request_id);
        }
    }
}

impl RequesterConnection {
    pub fn new(requester: Box<dyn ChatRequester>, self_aci: Option<libsignal_core::Aci>) -> Self {
        Self {
            requester: Arc::from(requester),
            self_aci,
            next_request_id: AtomicU64::new(0),
        }
    }

    /// The number this request is known by on both sides of the seam: the one its log lines
    /// carry, and the one `cancel` names if its future is dropped.
    fn allocate_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// One request through the requester, on tokio's blocking pool: the callback is synchronous
    /// by contract (C has to return before Rust continues), so it must not run on the worker
    /// the caller is awaiting on.
    ///
    /// The requester's own failure is a transport error; a reply it cannot be blamed for -- a
    /// status or header libsignal cannot represent -- is invalid incoming data. Both map to
    /// [`libsignal_net_chat::api::DisconnectedError::Transport`] above.
    ///
    /// Dropping this future is how a cancelled caller reaches the requester. It drops the
    /// `spawn_blocking` join handle, which abandons the blocking call rather than stopping it,
    /// so [`CancelOnDrop`] tells the requester by id that the reply is no longer wanted.
    async fn send_request(
        &self,
        request: Request,
        request_id: u64,
    ) -> Result<ChatResponse, SendError> {
        let Request {
            method,
            path,
            headers,
            body,
        } = request;
        let headers = headers
            .iter()
            .map(|(name, value)| {
                let value = value
                    .to_str()
                    .map_err(|_| SendError::RequestHasInvalidHeader)?;
                Ok(format!("{name}: {value}"))
            })
            .collect::<Result<Box<[String]>, SendError>>()?;
        let requester = Arc::clone(&self.requester);
        let cancel_on_drop = CancelOnDrop {
            requester: Arc::clone(&self.requester),
            request_id,
            armed: true,
        };
        let joined = tokio::task::spawn_blocking(move || {
            requester.send(
                request_id,
                method.to_string(),
                path.to_string(),
                headers,
                body.map(Vec::from).unwrap_or_default(),
            )
        })
        .await;
        // Before `?`: whichever way the call ended, it ended, and a request that has been
        // answered is not one to cancel.
        cancel_on_drop.disarm();
        let response = joined
            .map_err(|join_error| {
                log::error!("chat requester did not complete: {join_error}");
                SendError::Disconnected
            })?
            .map_err(|error| SendError::WebSocket(WebSocketError::Io(error)))?;

        let ChatRequesterResponse {
            status,
            headers,
            body,
        } = response;
        let status = http::StatusCode::from_u16(status).map_err(|_| {
            log::warn!("chat requester returned status {status}");
            SendError::IncomingDataInvalid
        })?;
        let mut header_map = HeaderMap::with_capacity(headers.len());
        for line in &headers {
            let (name, value) = line.split_once(':').ok_or(SendError::IncomingDataInvalid)?;
            let name =
                HeaderName::from_str(name.trim()).map_err(|_| SendError::IncomingDataInvalid)?;
            let value =
                HeaderValue::from_str(value.trim()).map_err(|_| SendError::IncomingDataInvalid)?;
            header_map.append(name, value);
        }
        let body = (!body.is_empty()).then(|| Bytes::from(body));
        Ok(ChatResponse {
            status,
            message: None,
            headers: header_map,
            body,
        })
    }
}

impl WsConnection for RequesterConnection {
    /// Logged the way [`ChatConnection`]'s sends are, so a request over a requester reads the
    /// same in a log as one over the socket.
    async fn send(
        &self,
        log_tag: &'static str,
        log_safe_path: &str,
        request: Request,
    ) -> Result<ChatResponse, SendError> {
        let request_id = self.allocate_request_id();
        let method = request.method.clone();
        log::info!("[{log_tag} {request_id:04x}] {method} {log_safe_path}");

        let result = self.send_request(request, request_id).await;

        match &result {
            Ok(response) => log::info!(
                "[{log_tag} {request_id:04x}] {method} {log_safe_path} {}",
                response.status
            ),
            Err(e) => log::warn!(
                "[{log_tag} {request_id:04x}] {method} {log_safe_path} - {}",
                e as &dyn LogSafeDisplay
            ),
        }

        result
    }

    fn self_aci(&self) -> Option<libsignal_core::Aci> {
        self.self_aci
    }
}

impl UnauthenticatedChatConnection {
    /// A connection with no socket: its requests go out through `requester`. Running from the
    /// start; there is no listener to wait for, and nothing arrives unasked.
    pub fn with_requester(requester: Box<dyn ChatRequester>) -> Self {
        Self {
            inner: MaybeChatConnection::Running(ChatWire::Requester(RequesterConnection::new(
                requester, None,
            )))
            .into(),
        }
    }

    pub async fn connect(
        connection_manager: &ConnectionManager,
        languages: LanguageList,
    ) -> Result<Self, ConnectError> {
        let pending = establish_chat_connection(
            "unauthenticated",
            connection_manager,
            CHAT_WEBSOCKET_PATH,
            Some(UnauthenticatedChatHeaders { languages }.into()),
        )
        .await?;
        let grpc_overrides = connection_manager.chat_grpc_overrides();
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener {
                runtime: tokio::runtime::Handle::current(),
                pending: pending.into(),
                grpc_overrides,
            }
            .into(),
        })
    }

    /// Provides access to the inner ChatConnection using the [`Unauth`] wrapper of
    /// libsignal-net-chat.
    ///
    /// This callback signature unfortunately requires boxing; there is not yet Rust syntax to say
    /// "I return an unknown Future that might capture from its arguments" in closure position
    /// specifically. It's also extra complicated to promise that the result doesn't have to outlive
    /// &self; unfortunately there doesn't seem to be a simpler way to express this at this time!
    /// (e.g. `for<'inner where 'outer: 'inner>`)
    pub async fn as_typed<'outer, F, R>(&'outer self, callback: F) -> R
    where
        F: for<'inner> FnOnce(
            LimitedLifetimeRef<'outer, 'inner, Unauth<ChatWire>>,
        ) -> BoxFuture<'inner, R>,
    {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        callback(LimitedLifetimeRef::from(<&Unauth<_>>::from(inner))).await
    }

    pub async fn require_grpc(&self) -> Unauth<impl libsignal_net_chat::grpc::GrpcServiceProvider> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        Unauth(
            inner
                .shared_h2_connection()
                .expect("requires an H2 connection"),
        )
    }

    pub fn blocking_require_grpc(
        &self,
    ) -> Unauth<impl libsignal_net_chat::grpc::GrpcServiceProvider + Clone + 'static> {
        let guard = self.as_ref().blocking_read();
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        Unauth(
            inner
                .shared_h2_connection()
                .expect("requires an H2 connection"),
        )
    }
}

impl AuthenticatedChatConnection {
    /// Given an HTTP Auth username of the form "{aci}" or "{aci}.{device_id}", parses and returns
    /// it.
    ///
    /// An absent device ID will be treated as device ID "1", consistent with the server's
    /// historical treatment of such usernames.
    ///
    /// Produces `None` on any other input (this is not a case where we need to know precisely what
    /// went wrong).
    pub fn parse_username(
        username: &str,
    ) -> Option<(libsignal_core::Aci, libsignal_core::DeviceId)> {
        const IMPLICIT_PRIMARY_DEVICE_ID_STR: &str = "1";
        let (aci_part, device_id_part) = username
            .rsplit_once('.')
            .unwrap_or((username, IMPLICIT_PRIMARY_DEVICE_ID_STR));
        let aci = libsignal_core::Aci::parse_from_service_id_string(aci_part)?;
        let device_id = libsignal_core::DeviceId::new_nonzero(
            std::num::NonZero::from_str(device_id_part).ok()?,
        )
        .ok()?;
        Some((aci, device_id))
    }

    /// A connection with no socket: its requests go out through `requester`, which is
    /// responsible for presenting the account's credentials on each of them. `aci` is the
    /// account's own, as the socket would have learned it from its auth username; the services
    /// that address the account itself (sync messages) read it from here.
    pub fn with_requester(requester: Box<dyn ChatRequester>, aci: libsignal_core::Aci) -> Self {
        Self {
            inner: MaybeChatConnection::Running(ChatWire::Requester(RequesterConnection::new(
                requester,
                Some(aci),
            )))
            .into(),
        }
    }

    pub async fn connect(
        connection_manager: &ConnectionManager,
        aci: libsignal_core::Aci,
        device_id: libsignal_core::DeviceId,
        password: String,
        receive_stories: bool,
        languages: LanguageList,
    ) -> Result<Self, ConnectError> {
        let pending = establish_chat_connection(
            "authenticated",
            connection_manager,
            CHAT_WEBSOCKET_PATH,
            Some(
                chat::AuthenticatedChatHeaders {
                    aci,
                    device_id,
                    password,
                    receive_stories: receive_stories.into(),
                    languages,
                }
                .into(),
            ),
        )
        .await?;
        let grpc_overrides = connection_manager.chat_grpc_overrides();
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener {
                runtime: tokio::runtime::Handle::current(),
                pending: pending.into(),
                grpc_overrides,
            }
            .into(),
        })
    }

    pub async fn preconnect(connection_manager: &ConnectionManager) -> Result<(), ConnectError> {
        let (enable_domain_fronting, enforce_minimum_tls) = {
            let endpoints_guard = connection_manager.endpoints.lock().expect("not poisoned");
            (
                endpoints_guard.enable_fronting,
                endpoints_guard.enforce_minimum_tls,
            )
        };
        let route_provider = make_route_provider(
            connection_manager,
            enable_domain_fronting,
            enforce_minimum_tls,
        )?
        .map_routes(|r| r.inner);
        let connection_resources = ConnectionResources {
            connect_state: &connection_manager.connect,
            dns_resolver: &connection_manager.dns_resolver,
            network_change_event: &connection_manager.network_change_event_tx.subscribe(),
            confirmation_header_name: None,
        };

        log::info!("preconnecting chat");
        connection_resources
            .preconnect_and_save(
                connection_manager.env.chat_domain_config.connect.service,
                route_provider,
                "preconnect",
            )
            .await?;
        Ok(())
    }

    /// Provides access to the inner ChatConnection using the [`Auth`](AuthConn) wrapper of
    /// libsignal-net-chat.
    ///
    /// This callback signature unfortunately requires boxing; there is not yet Rust syntax to say
    /// "I return an unknown Future that might capture from its arguments" in closure position
    /// specifically. It's also extra complicated to promise that the result doesn't have to outlive
    /// &self; unfortunately there doesn't seem to be a simpler way to express this at this time!
    /// (e.g. `for<'inner where 'outer: 'inner>`)
    pub async fn as_typed<'outer, F, R>(&'outer self, callback: F) -> R
    where
        F: for<'inner> FnOnce(
            LimitedLifetimeRef<'outer, 'inner, AuthConn<ChatWire>>,
        ) -> BoxFuture<'inner, R>,
    {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        callback(LimitedLifetimeRef::from(<&AuthConn<_>>::from(inner))).await
    }

    pub async fn require_grpc(
        &self,
    ) -> AuthConn<impl libsignal_net_chat::grpc::GrpcServiceProvider> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        AuthConn(
            inner
                .shared_h2_connection()
                .expect("requires an H2 connection"),
        )
    }
}

impl ProvisioningChatConnection {
    pub async fn connect(connection_manager: &ConnectionManager) -> Result<Self, ConnectError> {
        let pending = establish_chat_connection(
            "provisioning",
            connection_manager,
            CHAT_PROVISIONING_PATH,
            None,
        )
        .await?;
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener {
                runtime: tokio::runtime::Handle::current(),
                pending: pending.into(),
                grpc_overrides: Default::default(),
            }
            .into(),
        })
    }

    // Deliberately shadows the implementation on BridgeChatConnection, which takes the wrong kind
    // of listener. Nothing *prevents* calling that on a ProvisioningChatConnection, but it won't be
    // very useful, so don't do that.
    pub fn init_listener(&self, listener: Box<dyn ProvisioningListener>) {
        init_listener(
            &mut self.as_ref().blocking_write(),
            listener.into_event_listener(),
        )
    }
}

impl AsRef<tokio::sync::RwLock<MaybeChatConnection>> for AuthenticatedChatConnection {
    fn as_ref(&self) -> &tokio::sync::RwLock<MaybeChatConnection> {
        &self.inner
    }
}

impl AsRef<tokio::sync::RwLock<MaybeChatConnection>> for UnauthenticatedChatConnection {
    fn as_ref(&self) -> &tokio::sync::RwLock<MaybeChatConnection> {
        &self.inner
    }
}

impl AsRef<tokio::sync::RwLock<MaybeChatConnection>> for ProvisioningChatConnection {
    fn as_ref(&self) -> &tokio::sync::RwLock<MaybeChatConnection> {
        &self.inner
    }
}

pub trait BridgeChatConnection {
    fn init_listener(&self, listener: Box<dyn ChatListener>);

    fn send(
        &self,
        message: Request,
        timeout: Duration,
    ) -> impl Future<Output = Result<ChatResponse, SendError>> + Send;

    fn disconnect(&self) -> impl Future<Output = ()> + Send;

    fn info(&self) -> ConnectionInfo;
}

impl<C: AsRef<tokio::sync::RwLock<MaybeChatConnection>> + Sync> BridgeChatConnection for C {
    fn init_listener(&self, listener: Box<dyn ChatListener>) {
        init_listener(
            &mut self.as_ref().blocking_write(),
            listener.into_event_listener(),
        )
    }

    async fn send(&self, message: Request, timeout: Duration) -> Result<ChatResponse, SendError> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        inner.send(message, timeout).await
    }

    async fn disconnect(&self) {
        let guard = self.as_ref().read().await;
        match &*guard {
            MaybeChatConnection::Running(chat_connection) => chat_connection.disconnect().await,
            MaybeChatConnection::WaitingForListener {
                runtime: _,
                pending,
                grpc_overrides: _,
            } => pending.lock().await.disconnect().await,
            MaybeChatConnection::TemporarilyEvicted => {
                unreachable!("unobservable state");
            }
        }
    }

    fn info(&self) -> ConnectionInfo {
        let guard = self.as_ref().blocking_read();
        match &*guard {
            MaybeChatConnection::Running(chat_connection) => chat_connection
                .connection_info()
                .expect("a requester-backed connection has no socket to describe")
                .clone(),
            MaybeChatConnection::WaitingForListener {
                runtime: _,
                pending,
                grpc_overrides: _,
            } => pending.blocking_lock().connection_info(),
            MaybeChatConnection::TemporarilyEvicted => unreachable!("unobservable state"),
        }
    }
}

pub(crate) async fn connect_registration_chat(
    tokio_runtime: &tokio::runtime::Handle,
    connection_manager: &ConnectionManager,
    drop_on_disconnect: tokio::sync::oneshot::Sender<Infallible>,
) -> Result<Unauth<ChatConnection>, ConnectError> {
    let pending = establish_chat_connection(
        "registration",
        connection_manager,
        CHAT_WEBSOCKET_PATH,
        None,
    )
    .await?;

    let mut on_disconnect = Some(drop_on_disconnect);
    let listener = move |event| match event {
        ListenerEvent::Finished(_) => drop(on_disconnect.take()),
        ListenerEvent::ServerTimestamp(_)
        | ListenerEvent::ReceivedAlerts(_)
        | ListenerEvent::ReceivedMessage(_, _) => (),
    };

    Ok(Unauth(ChatConnection::finish_connect(
        tokio_runtime.clone(),
        pending,
        Default::default(),
        Box::new(listener),
    )))
}

fn init_listener(connection: &mut MaybeChatConnection, listener: chat::ws::EventListener) {
    let (tokio_runtime, pending, grpc_overrides) =
        match std::mem::replace(connection, MaybeChatConnection::TemporarilyEvicted) {
            MaybeChatConnection::Running(chat_connection) => {
                *connection = MaybeChatConnection::Running(chat_connection);
                panic!("listener already set")
            }
            MaybeChatConnection::WaitingForListener {
                runtime,
                pending,
                grpc_overrides,
            } => (runtime, pending, grpc_overrides),
            MaybeChatConnection::TemporarilyEvicted => panic!("should be a temporary state"),
        };

    *connection = MaybeChatConnection::Running(ChatWire::Ws(ChatConnection::finish_connect(
        tokio_runtime,
        pending.into_inner(),
        grpc_overrides,
        listener,
    )))
}

pub struct FakeChatConnection(ChatConnection);

impl FakeChatConnection {
    pub fn new<'a>(
        tokio_runtime: tokio::runtime::Handle,
        listener: chat::ws::EventListener,
        grpc_overrides: impl IntoIterator<Item = &'static str>,
        alerts: impl IntoIterator<Item = &'a str>,
    ) -> (Self, FakeChatRemote) {
        let (inner, remote) =
            ChatConnection::new_fake(tokio_runtime, listener, grpc_overrides, alerts);
        (Self(inner), remote)
    }

    pub fn into_unauthenticated(self) -> UnauthenticatedChatConnection {
        let Self(inner) = self;
        UnauthenticatedChatConnection {
            inner: MaybeChatConnection::Running(ChatWire::Ws(inner)).into(),
        }
    }

    pub fn into_authenticated(self) -> AuthenticatedChatConnection {
        let Self(inner) = self;
        AuthenticatedChatConnection {
            inner: MaybeChatConnection::Running(ChatWire::Ws(inner)).into(),
        }
    }

    pub fn into_provisioning(self) -> ProvisioningChatConnection {
        let Self(inner) = self;
        ProvisioningChatConnection {
            inner: MaybeChatConnection::Running(ChatWire::Ws(inner)).into(),
        }
    }
}

async fn establish_chat_connection(
    kind: &'static str,
    connection_manager: &ConnectionManager,
    endpoint_path: &'static str,
    headers: Option<chat::ChatHeaders>,
) -> Result<chat::PendingChatConnection, ConnectError> {
    let ConnectionManager {
        env,
        dns_resolver,
        connect,
        user_agent,
        endpoints,
        network_change_event_tx,
        remote_config,
        ..
    } = connection_manager;

    let (enable_domain_fronting, enforce_minimum_tls) = {
        let endpoints_guard = endpoints.lock().expect("not poisoned");
        (
            endpoints_guard.enable_fronting,
            endpoints_guard.enforce_minimum_tls,
        )
    };

    let chat_connect = &env.chat_domain_config.connect;
    let connection_resources = ConnectionResources {
        connect_state: connect,
        dns_resolver,
        network_change_event: &network_change_event_tx.subscribe(),
        confirmation_header_name: chat_connect
            .confirmation_header_name
            .map(HeaderName::from_static),
    };
    let route_provider = make_route_provider(
        connection_manager,
        enable_domain_fronting,
        enforce_minimum_tls,
    )?;
    let proxy_mode = DirectOrProxyModeDiscriminants::from(&route_provider.mode);

    log::info!("connecting {kind} chat");

    let mut chat_ws_config = env.chat_ws_config;
    let timeout_millis = {
        let guard = remote_config.lock().expect("unpoisoned");
        guard.get(RemoteConfigKey::ChatRequestConnectionCheckTimeoutMilliseconds)
    };
    if let Some(timeout_millis) = timeout_millis
        .as_option()
        .and_then(|v| match u64::from_str(v) {
            Ok(v) => Some(v),
            Err(e) => {
                log::error!(
                    "bad {}: {v:?} ({e})",
                    RemoteConfigKey::ChatRequestConnectionCheckTimeoutMilliseconds
                );
                None
            }
        })
    {
        chat_ws_config.post_request_interface_check_timeout = Duration::from_millis(timeout_millis);
    }

    ChatConnection::start_connect_with(
        connection_resources,
        env.chat_domain_config.connect.service,
        route_provider,
        endpoint_path,
        user_agent,
        chat_ws_config,
        headers,
        kind,
    )
    .inspect(|r| match r {
        Ok(connection) => {
            match (
                connection.connection_info().route_info.unresolved.proxy,
                proxy_mode,
            ) {
                (None, DirectOrProxyModeDiscriminants::DirectOnly)
                | (None, DirectOrProxyModeDiscriminants::DirectThenProxy)
                | (Some(_), DirectOrProxyModeDiscriminants::ProxyOnly)
                | (Some(_), DirectOrProxyModeDiscriminants::ProxyThenDirect)
                | (Some(_), DirectOrProxyModeDiscriminants::DirectThenProxy) => {
                    log::info!("successfully connected {kind} chat")
                }
                (None, DirectOrProxyModeDiscriminants::ProxyThenDirect) => log::warn!(
                    "connected {kind} chat using a direct connection rather than the specified proxy"
                ),
                (None, DirectOrProxyModeDiscriminants::ProxyOnly) => unreachable!(
                    "made a direct connection despite using only proxy routes; this is a bug in libsignal"
                ),
                (Some(_), DirectOrProxyModeDiscriminants::DirectOnly) => unreachable!(
                    "made a proxy connection despite not having proxy config; this is a bug in libsignal"
                ),
            }
        }
        Err(e) => log::warn!("failed to connect {kind} chat: {e}"),
    })
    .await
}

fn make_route_provider(
    connection_manager: &ConnectionManager,
    enable_domain_fronting: EnableDomainFronting,
    enforce_minimum_tls: EnforceMinimumTls,
) -> Result<
    DirectOrProxyProvider<
        impl RouteProvider<
            Route = UnresolvedHttpsServiceRoute<
                TlsRoute<TcpRoute<libsignal_net::infra::route::UnresolvedHost>>,
            >,
        > + use<>,
    >,
    ConnectError,
> {
    let ConnectionManager {
        env,
        transport_connector,
        ..
    } = connection_manager;

    let proxy_mode: DirectOrProxyMode = (&*transport_connector.lock().expect("not poisoned"))
        .try_into()
        .map_err(|InvalidProxyConfig| ConnectError::InvalidConnectionConfiguration)?;

    let chat_connect = &env.chat_domain_config.connect;

    let inner = chat_connect.route_provider_with_options(
        enable_domain_fronting,
        enforce_minimum_tls,
        OverrideNagleAlgorithm::OverrideToOff,
    );
    Ok(DirectOrProxyProvider {
        inner,
        mode: proxy_mode,
    })
}

pub struct HttpRequest {
    pub method: http::Method,
    pub path: PathAndQuery,
    pub body: Option<Bytes>,
    pub headers: std::sync::Mutex<HeaderMap>,
}

pub struct ResponseAndDebugInfo {
    pub response: ChatResponse,
    pub debug_info: ChatServiceDebugInfo,
}

bridge_as_handle!(HttpRequest);

/// Newtype wrapper for implementing [`TryFrom`]`
pub struct HttpMethod(http::Method);

impl TryFrom<String> for HttpMethod {
    type Error = <http::Method as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value).map(Self)
    }
}

#[derive(derive_more::Into)]
pub struct HttpStatus(http::StatusCode);

impl TryFrom<u16> for HttpStatus {
    type Error = InvalidStatusCode;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        http::StatusCode::from_u16(value).map(Self)
    }
}

impl HttpRequest {
    pub fn new(
        method: HttpMethod,
        path: String,
        body_as_slice: Option<&[u8]>,
    ) -> Result<Self, InvalidUri> {
        let body = body_as_slice.map(Bytes::copy_from_slice);
        let method = method.0;
        let path = path.try_into()?;
        Ok(HttpRequest {
            method,
            path,
            body,
            headers: Default::default(),
        })
    }

    pub fn add_header(&self, name: HeaderName, value: HeaderValue) {
        let mut guard = self.headers.lock().expect("not poisoned");
        guard.append(name, value);
    }
}

/// A trait of callbacks for different kinds of [`chat::server_requests::ServerEvent`].
///
/// Done as multiple functions so we can adjust the types to be more suitable for bridging.
#[bridge_callbacks(jni = "org.signal.libsignal.net.internal.BridgeChatListener")]
pub trait ChatListener: Send {
    fn received_incoming_message(
        &mut self,
        envelope: bytes::Bytes,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    );
    fn received_queue_empty(&mut self);
    fn received_alerts(&mut self, alerts: Box<[String]>);
    fn received_server_timestamp(&mut self, timestamp: Timestamp);
    fn connection_interrupted(&mut self, disconnect_cause: Option<BridgedError<SendError>>);
}

impl dyn ChatListener {
    /// A helper to translate from the libsignal-net enum to the separate callback methods in this
    /// trait.
    fn received_server_request(&mut self, request: chat::server_requests::ServerEvent) {
        match request {
            chat::server_requests::ServerEvent::IncomingMessage {
                request_id: _,
                envelope,
                server_delivery_timestamp,
                send_ack,
            } => self.received_incoming_message(
                envelope,
                server_delivery_timestamp,
                ServerMessageAck::new(send_ack),
            ),
            chat::server_requests::ServerEvent::QueueEmpty => self.received_queue_empty(),
            chat::server_requests::ServerEvent::Alerts(alerts) => {
                self.received_alerts(alerts.into_boxed_slice())
            }
            chat::server_requests::ServerEvent::ServerTimestamp(timestamp) => {
                self.received_server_timestamp(timestamp)
            }
            chat::server_requests::ServerEvent::Stopped(error) => {
                self.connection_interrupted(match error {
                    DisconnectCause::LocalDisconnect => None,
                    DisconnectCause::Error(send_error) => Some(send_error.into()),
                })
            }
        }
    }

    pub fn into_event_listener(mut self: Box<Self>) -> chat::ws::EventListener {
        Box::new(move |event| {
            let event: chat::server_requests::ServerEvent = match event.try_into() {
                Ok(event) => event,
                Err(err) => {
                    log::error!("{err}");
                    return;
                }
            };
            self.received_server_request(event);
        })
    }
}

/// Wraps a named type and a single-use guard around [`chat::server_requests::ResponseEnvelopeSender`].
pub struct ServerMessageAck {
    inner: AtomicTake<chat::server_requests::ResponseEnvelopeSender>,
}

impl ServerMessageAck {
    pub fn new(send_ack: chat::server_requests::ResponseEnvelopeSender) -> Self {
        Self {
            inner: AtomicTake::new(send_ack),
        }
    }

    pub fn take(&self) -> Option<chat::server_requests::ResponseEnvelopeSender> {
        self.inner.take()
    }
}

bridge_as_handle!(ServerMessageAck);

// `AtomicTake` disables its auto `Sync` impl by using a `PhantomData<UnsafeCell>`, but that also
// makes it `!RefUnwindSafe`. We're putting that back; because we only manipulate the `AtomicTake`
// using its atomic operations, it can never be in an invalid state.
impl std::panic::RefUnwindSafe for ServerMessageAck {}

/// A trait of callbacks for different kinds of [`chat::server_requests::ProvisioningEvent`].
///
/// Done as multiple functions so we can adjust the types to be more suitable for bridging.
#[bridge_callbacks(jni = "org.signal.libsignal.net.internal.BridgeProvisioningListener")]
pub trait ProvisioningListener: Send {
    fn received_address(&mut self, address: String, send_ack: ServerMessageAck);
    fn received_envelope(&mut self, envelope: bytes::Bytes, send_ack: ServerMessageAck);
    fn connection_interrupted(&mut self, disconnect_cause: Option<BridgedError<SendError>>);
}

impl dyn ProvisioningListener {
    /// A helper to translate from the libsignal-net enum to the separate callback methods in this
    /// trait.
    fn received_server_request(&mut self, request: chat::server_requests::ProvisioningEvent) {
        match request {
            chat::server_requests::ProvisioningEvent::ServerTimestamp(_) => {
                // For now, we don't expose this to the apps.
            }
            chat::server_requests::ProvisioningEvent::ReceivedAddress { address, send_ack } => {
                self.received_address(address, ServerMessageAck::new(send_ack))
            }
            chat::server_requests::ProvisioningEvent::ReceivedEnvelope { envelope, send_ack } => {
                self.received_envelope(envelope, ServerMessageAck::new(send_ack))
            }
            chat::server_requests::ProvisioningEvent::Stopped(error) => self
                .connection_interrupted(match error {
                    DisconnectCause::LocalDisconnect => None,
                    DisconnectCause::Error(send_error) => Some(send_error.into()),
                }),
        }
    }

    pub fn into_event_listener(mut self: Box<Self>) -> chat::ws::EventListener {
        Box::new(move |event| {
            if let ListenerEvent::ReceivedAlerts(alerts) = &event {
                if !alerts.is_empty() {
                    log::warn!(
                        "unexpected alerts on provisioning connection: {}",
                        alerts.join(",")
                    );
                }
                return;
            }
            let event: chat::server_requests::ProvisioningEvent = match event.try_into() {
                Ok(event) => event,
                Err(err) => {
                    log::error!("{err}");
                    return;
                }
            };
            self.received_server_request(event);
        })
    }
}

pub struct PreKeysResponse {
    pub identity_key: IdentityKey,
    pub pre_key_bundles: Vec<PreKeyBundle>,
}

// Must be kept in sync with the app languages.
#[repr(u8)]
#[derive(derive_more::TryFrom)]
#[try_from(repr)]
pub enum UserBasedSendAuthorizationKind {
    Story,
    AccessKey,
    Group,
    UnrestrictedUnauthenticatedAccess,
}

#[derive(BridgedAsValue)]
pub struct BridgeCopyBackupMediaItem {
    pub source_attachment_cdn: i32,
    pub source_key: String,
    pub object_length: i64,
    pub media_id: [u8; MEDIA_ID_LEN],
    pub encryption_key: [u8; MEDIA_ENCRYPTION_KEY_LEN],
}

// TODO: This can go away when we implement u32 and u64 Nice bridging to Kotlin.
#[derive(BridgedAsValue)]
#[bridge(arg = false)]
pub struct BridgeMessageBackupInfo {
    pub backup_dir: String,
    pub cdn: i32,
    pub backup_name: String,
}

impl From<MessageBackupInfo> for BridgeMessageBackupInfo {
    fn from(value: MessageBackupInfo) -> Self {
        Self {
            backup_dir: value.backup_dir,
            cdn: value.cdn.try_into().expect("CDN numbers are small"),
            backup_name: value.backup_name,
        }
    }
}

#[derive(BridgedAsValue)]
#[bridge(arg = false)]
pub struct BridgeMediaBackupInfo {
    pub backup_dir: String,
    pub media_dir: String,
    pub used_space: i64,
}

impl From<MediaBackupInfo> for BridgeMediaBackupInfo {
    fn from(value: MediaBackupInfo) -> Self {
        Self {
            backup_dir: value.backup_dir,
            media_dir: value.media_dir,
            used_space: value
                .used_space
                .try_into()
                .expect("space measurements fit in i64"),
        }
    }
}

impl From<CopyBackupMediaItem> for BridgeCopyBackupMediaItem {
    fn from(value: CopyBackupMediaItem) -> Self {
        Self {
            source_attachment_cdn: value
                .source_attachment_cdn
                .try_into()
                .expect("CDN numbers are small"),
            source_key: value.source_key,
            object_length: value
                .object_length
                .try_into()
                .expect("object lengths fit in i64"),
            media_id: value.media_id,
            encryption_key: value.encryption_key,
        }
    }
}

#[derive(BridgedAsValue)]
pub struct BridgeCopyBackupMediaOutcome {
    pub media_id: [u8; MEDIA_ID_LEN],
    pub result: BridgeCopyBackupMediaResult,
}

impl From<CopyBackupMediaOutcome> for BridgeCopyBackupMediaOutcome {
    fn from(value: CopyBackupMediaOutcome) -> Self {
        Self {
            media_id: value.media_id,
            result: match value.cdn_or_failure {
                Ok(cdn) => BridgeCopyBackupMediaResult::Success {
                    cdn: cdn.try_into().expect("CDN numbers are small"),
                },
                Err(CopyBackupMediaFailure::OutOfSpace) => BridgeCopyBackupMediaResult::OutOfSpace,
                Err(CopyBackupMediaFailure::SourceNotFound) => {
                    BridgeCopyBackupMediaResult::SourceNotFound
                }
                Err(CopyBackupMediaFailure::WrongSourceLength) => {
                    BridgeCopyBackupMediaResult::WrongSourceLength
                }
            },
        }
    }
}

#[derive(BridgedAsValue)]
pub enum BridgeCopyBackupMediaResult {
    Success { cdn: i32 },
    SourceNotFound,
    WrongSourceLength,
    OutOfSpace,
}

#[derive(Debug)]
pub struct StreamCancelled;

pub struct BridgeBulkPolledStream<T, E> {
    #[expect(clippy::type_complexity)]
    state: AsyncMutex<Option<BulkPolledStream<BoxStream<'static, Result<T, E>>>>>,
    cancelled: tokio::sync::watch::Sender<bool>,
}

impl<T, E> BridgeBulkPolledStream<T, E> {
    /// Wraps `stream` for bulk-polling (and cancellation).
    ///
    /// The chunk size should be chosen based on the following criteria:
    /// - How much does bridging cost, relative to consumer-side throughput? (lower limit)
    /// - How much client memory will this allocate for a full chunk? (upper limit)
    ///
    /// It is not especially affected by
    /// - High producer-side throughput (nearly any chunk size will induce backpressure)
    /// - Low producer-side throughput (nearly any chunk size will not be reached anyway)
    /// - Producer-side latency (the first element may be delayed but hopefully the rest will arrive
    ///   soon after)
    ///
    /// The debounce time should be chosen based on the following criteria:
    /// - How much does bridging cost, relative to consumer-side throughput? (lower limit)
    /// - How long can the consumer tolerate a lack of updates, relative to producer-side
    ///   throughput? (upper limit)
    /// - How much *uneven* latency is there on the connection? (lower and upper limit)
    ///
    /// If you don't have any extra information, [`BULK_POLLED_STREAM_DEFAULT_CHUNK_SIZE`] and
    /// [`BULK_POLLED_STREAM_DEFAULT_DEBOUNCE_TIME`] were chosen to be non-terrible values for an
    /// average stream.
    pub fn new(
        stream: impl Stream<Item = Result<T, E>> + Send + 'static,
        max_chunk_size: usize,
        debounce_time: Duration,
    ) -> Self {
        Self {
            state: AsyncMutex::from(Some(BulkPolledStream::new(
                stream.boxed(),
                max_chunk_size,
                debounce_time,
            ))),
            cancelled: Default::default(),
        }
    }

    pub async fn next_chunk(&self) -> Result<BulkPolledStreamChunk<T, E>, StreamCancelled> {
        let mut cancelled = self.cancelled.subscribe();
        let lock_and_poll_stream = async {
            Ok(self
                .state
                .lock()
                .await
                .as_mut()
                .ok_or(StreamCancelled)?
                .next_chunk_unpin()
                .await)
        };

        // The "biased" isn't necessary for correctness, but it's simpler to reason about.
        tokio::select! { biased;
            _ = cancelled.wait_for(|flag| *flag) => Err(StreamCancelled),
            result = lock_and_poll_stream => result,
        }
    }

    pub fn cancel(&self) {
        // First signal any tasks to exit.
        _ = self.cancelled.send_replace(true);
        // Wait for exits, then destroy the state.
        _ = self.state.blocking_lock().take();
    }
}

/// A "reasonable" default value to use for bulk-polled streaming network APIs.
///
/// Chosen only for being neither too small (thus wasting time in the bridge layer processing many
/// small chunks) nor too large (thus allocating a bunch of memory at once).
pub const BULK_POLLED_STREAM_DEFAULT_CHUNK_SIZE: usize = 64;

/// A "reasonable" default value to use for bulk-polled streaming network APIs.
///
/// Chosen only for being neither too short (thus wasting time in the bridge layer processing many
/// small chunks) nor too long (thus delaying reporting progress in a user-visible way).
pub const BULK_POLLED_STREAM_DEFAULT_DEBOUNCE_TIME: Duration = Duration::from_millis(100);

#[derive(BridgedAsValue)]
#[bridge(arg = false)]
pub struct CopyBackupMediaNextChunk {
    pub chunk: BridgeVec<BridgeCopyBackupMediaOutcome>,
    pub termination:
        Option<BulkPolledStreamTerminationReason<RequestError<BackupAuthCredentialRejected>>>,
}

#[derive(derive_more::From, derive_more::Deref)]
pub struct CopyBackupMediaStream(
    BridgeBulkPolledStream<CopyBackupMediaOutcome, RequestError<BackupAuthCredentialRejected>>,
);

bridge_as_handle!(
    CopyBackupMediaStream,
    swift_type = "CopyBackupMediaStream",
    jni_class = "org.signal.libsignal.net.internal.CopyBackupMediaStream",
);

#[derive(BridgedAsValue)]
pub struct BridgeDeleteBackupMediaItem {
    pub media_id: [u8; MEDIA_ID_LEN],
    pub cdn: i32,
}

impl From<DeleteBackupMediaItem> for BridgeDeleteBackupMediaItem {
    fn from(value: DeleteBackupMediaItem) -> Self {
        Self {
            media_id: value.media_id,
            cdn: value.cdn.try_into().expect("CDN numbers are small"),
        }
    }
}

#[derive(BridgedAsValue)]
#[bridge(arg = false)]
pub struct DeleteBackupMediaNextChunk {
    pub chunk: BridgeVec<BridgeDeleteBackupMediaItem>,
    pub termination:
        Option<BulkPolledStreamTerminationReason<RequestError<BackupAuthCredentialRejected>>>,
}

#[derive(derive_more::From, derive_more::Deref)]
pub struct DeleteBackupMediaStream(
    BridgeBulkPolledStream<BridgeDeleteBackupMediaItem, RequestError<BackupAuthCredentialRejected>>,
);

bridge_as_handle!(
    DeleteBackupMediaStream,
    swift_type = "DeleteBackupMediaStream",
    jni_class = "org.signal.libsignal.net.internal.DeleteBackupMediaStream",
);

pub mod remote_derives {
    use libsignal_bridge_macros::StructuralFrom;
    use libsignal_core::DeviceId;

    use super::*;

    #[derive(BridgedAsValue)]
    #[bridge(remote = libsignal_net_chat::grpc::devices::LinkedDevice)]
    #[allow(unused)]
    pub struct LinkedDeviceInternal {
        pub id: DeviceId,
        pub encrypted_name: Vec<u8>,
        pub last_seen: Timestamp,
        pub registration_id: u16,
        pub created_at_ciphertext: Vec<u8>,
    }

    #[derive(BridgedAsValue)]
    pub struct ListMediaItem {
        pub cdn: i32,
        pub media_id: [u8; MEDIA_ID_LEN],
        pub object_length: i64,
    }

    impl From<libsignal_net_chat::grpc::backups::ListMediaItem> for ListMediaItem {
        fn from(value: libsignal_net_chat::grpc::backups::ListMediaItem) -> Self {
            let libsignal_net_chat::grpc::backups::ListMediaItem {
                cdn,
                media_id,
                object_length,
            } = value;
            Self {
                cdn: cdn.try_into().expect("CDN numbers are small"),
                media_id,
                object_length: object_length.try_into().expect("object lengths fit in i64"),
            }
        }
    }

    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::backups::ListMediaResponse)]
    #[bridge(arg = false)]
    pub struct ListMediaResponse {
        /// The requested page of items.
        pub items: BridgeVec<ListMediaItem>,
        /// The base directory of the backup data on the CDN.
        ///
        /// Always non-empty, even if no media has been stored to the CDN or the credential is for a
        /// tier that does not support media.
        pub backup_dir: String,
        /// The prefix path component for media objects on a CDN.
        ///
        /// Stored media for a `media_id` can be found at `/backup_dir/media_dir/media_id`, where the
        /// `media_id` is encoded in unpadded url-safe base64. Always non-empty, even if no media has
        /// been stored to the CDN or the credential is for a tier that does not support media.
        pub media_dir: String,
        /// If set, the cursor value to pass to the next list request to continue listing. If absent,
        /// all objects have been listed.
        pub cursor: Option<String>,
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;

    const TEST_UUID: uuid::Uuid = uuid::uuid!("659aa5f4-a28d-fcc1-1ea1-b997537a3d95");

    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(1).expect("valid"))))]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.1" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(1).expect("valid"))))]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.123" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(123).expect("valid"))))]
    #[test_case("659AA5F4-A28D-FCC1-1EA1-B997537A3D95.124" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(124).expect("valid"))))]
    #[test_case("659aA5f4-A28d-FcC1-1eA1-b997537A3d95.125" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(125).expect("valid"))))]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d9" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95." => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.a" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.0" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.2.3" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.128" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.9999" => None)]
    #[test_case(".123" => None)]
    #[test_case("a.123" => None)]
    #[test_case("a" => None)]
    fn test_parse_username(input: &str) -> Option<(libsignal_core::Aci, libsignal_core::DeviceId)> {
        AuthenticatedChatConnection::parse_username(input)
    }

    #[tokio::test]
    async fn bulk_polled_stream_cancel_with_next_chunk_in_flight() {
        let stream = Arc::new(
            BridgeBulkPolledStream::<String, std::convert::Infallible>::new(
                futures_util::stream::pending(),
                5,
                Duration::ZERO,
            ),
        );

        let next_chunk_task = tokio::task::spawn({
            let stream = stream.clone();
            async move { stream.next_chunk().await }
        });
        // Make sure the task acquires the lock.
        tokio::task::yield_now().await;

        // Cancel from an "app" thread, the way a bridge_fn would be called.
        let (cancel_done_tx, cancel_done_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            stream.cancel();
            _ = cancel_done_tx.send(());
        });

        () = tokio::time::timeout(Duration::from_secs(1), cancel_done_rx)
            .await
            .expect("cancel() should return promptly even with a next_chunk in flight")
            .expect("should have been explicitly signalled");

        let result = tokio::time::timeout(Duration::from_secs(1), next_chunk_task)
            .await
            .expect("in-flight next_chunk should resolve once cancelled")
            .expect("should not have panicked");
        assert_matches!(result, Err(StreamCancelled));
    }

    #[tokio::test]
    async fn bulk_polled_stream_cancel_in_advance() {
        let stream = Arc::new(
            BridgeBulkPolledStream::<String, std::convert::Infallible>::new(
                futures_util::stream::pending(),
                5,
                Duration::ZERO,
            ),
        );

        // Cancel from an "app" thread, the way a bridge_fn would be called.
        let (cancel_done_tx, cancel_done_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn({
            let stream = stream.clone();
            move || {
                stream.cancel();
                _ = cancel_done_tx.send(());
            }
        });

        () = tokio::time::timeout(Duration::from_secs(1), cancel_done_rx)
            .await
            .expect("cancel() should return promptly")
            .expect("should have been explicitly signalled");

        let result = tokio::time::timeout(Duration::from_secs(1), stream.next_chunk())
            .await
            .expect("in-flight next_chunk should resolve once cancelled");
        assert_matches!(result, Err(StreamCancelled));
    }
}

/// A typed service over a [`ChatRequester`]: the seam, exercised without the FFI.
///
/// `account_exists` is the service used because it is the smallest one (a HEAD, a status), so
/// what these tests see is the wire's own behaviour: how the request reaches the requester, how
/// the reply's status and headers come back through libsignal's decoders, and which errors are
/// the requester's and which are the server's.
#[cfg(test)]
mod requester_tests {
    use std::sync::Mutex;

    use assert_matches::assert_matches;
    use libsignal_net::infra::errors::RetryLater;
    use libsignal_net_chat::api::DisconnectedError;
    use libsignal_net_chat::api::profiles::UnauthenticatedAccountExistenceApi as _;

    use super::*;

    const ACI: libsignal_core::Aci = libsignal_core::Aci::from_uuid_bytes(
        uuid::uuid!("659aa5f4-a28d-fcc1-1ea1-b997537a3d95").into_bytes(),
    );

    struct Seen {
        request_id: u64,
        method: String,
        path: String,
        headers: Vec<String>,
        body: Vec<u8>,
    }

    /// What a test keeps hold of after the connection has taken ownership of the requester:
    /// every request it was asked to make, and every id it was told to let go of.
    #[derive(Default)]
    struct Record {
        seen: Mutex<Vec<Seen>>,
        cancelled: Mutex<Vec<u64>>,
    }

    /// Answers every request the same way and records what it was asked.
    struct Canned {
        status: u16,
        headers: Vec<&'static str>,
        body: &'static [u8],
        failure: Option<&'static str>,
        record: Arc<Record>,
    }

    impl Canned {
        fn answering(status: u16, headers: &[&'static str], body: &'static [u8]) -> Self {
            Self {
                status,
                headers: headers.to_vec(),
                body,
                failure: None,
                record: Default::default(),
            }
        }

        fn failing(reason: &'static str) -> Self {
            Self {
                failure: Some(reason),
                ..Self::answering(0, &[], b"")
            }
        }
    }

    impl ChatRequester for Canned {
        fn send(
            &self,
            request_id: u64,
            method: String,
            path: String,
            headers: Box<[String]>,
            body: Vec<u8>,
        ) -> Result<ChatRequesterResponse, std::io::Error> {
            self.record.seen.lock().expect("not poisoned").push(Seen {
                request_id,
                method,
                path,
                headers: headers.into_vec(),
                body,
            });
            if let Some(reason) = self.failure {
                return Err(std::io::Error::other(reason));
            }
            Ok(ChatRequesterResponse {
                status: self.status,
                headers: self.headers.iter().map(|h| h.to_string()).collect(),
                body: self.body.to_vec(),
            })
        }

        fn cancel(&self, request_id: u64) {
            self.record
                .cancelled
                .lock()
                .expect("not poisoned")
                .push(request_id);
        }
    }

    async fn account_exists(
        requester: Canned,
    ) -> (Result<bool, RequestError<Infallible>>, Arc<Record>) {
        let record = Arc::clone(&requester.record);
        let connection = UnauthenticatedChatConnection::with_requester(Box::new(requester));
        let result = connection
            .as_typed(|chat| chat.account_exists(ACI.into()))
            .await;
        (result, record)
    }

    fn requests(record: &Record) -> std::sync::MutexGuard<'_, Vec<Seen>> {
        record.seen.lock().expect("not poisoned")
    }

    fn cancelled(record: &Record) -> Vec<u64> {
        record.cancelled.lock().expect("not poisoned").clone()
    }

    #[tokio::test]
    async fn a_typed_service_runs_over_the_requester() {
        let (result, record) = account_exists(Canned::answering(200, &[], b"")).await;
        assert_matches!(result, Ok(true));
        let seen = requests(&record);
        let [request] = seen.as_slice() else {
            panic!("expected one request, saw {}", seen.len())
        };
        // The id a requester is handed is the connection's own count, from zero, and is the
        // number the request's log lines carry -- so a `cancel` naming it can be matched
        // against them.
        assert_eq!(request.request_id, 0);
        assert_eq!(request.method, "HEAD");
        assert_eq!(
            request.path,
            "/v1/accounts/account/659aa5f4-a28d-fcc1-1ea1-b997537a3d95"
        );
        assert!(request.headers.is_empty(), "{:?}", request.headers);
        assert!(request.body.is_empty());
    }

    #[tokio::test]
    async fn the_servers_answer_is_the_services_answer() {
        let (result, _) = account_exists(Canned::answering(404, &[], b"")).await;
        assert_matches!(result, Ok(false));
    }

    #[tokio::test]
    async fn response_headers_reach_the_decoder() {
        let (result, _) = account_exists(Canned::answering(
            429,
            &["Content-Type: application/json", "Retry-After: 7"],
            b"{}",
        ))
        .await;
        assert_matches!(
            result,
            Err(RequestError::RetryLater(RetryLater {
                retry_after_seconds: 7
            }))
        );
    }

    #[tokio::test]
    async fn the_requesters_failure_is_a_transport_error() {
        let (result, record) = account_exists(Canned::failing("the proxy is down")).await;
        assert_matches!(
            result,
            Err(RequestError::Disconnected(
                DisconnectedError::Transport { .. }
            ))
        );
        assert_eq!(requests(&record).len(), 1);
    }

    #[tokio::test]
    async fn a_reply_libsignal_cannot_represent_is_a_transport_error() {
        let (result, _) = account_exists(Canned::answering(200, &["not a header"], b"")).await;
        assert_matches!(
            result,
            Err(RequestError::Disconnected(
                DisconnectedError::Transport { .. }
            ))
        );
    }

    /// A request that ran to an answer, or to a failure, is finished; nothing is holding the
    /// wire, so nothing is told to let go of it. `cancel` names abandoned requests only.
    #[tokio::test]
    async fn a_request_that_completed_is_never_cancelled() {
        let (result, record) = account_exists(Canned::answering(200, &[], b"")).await;
        assert_matches!(result, Ok(true));
        assert_eq!(cancelled(&record), &[] as &[u64]);

        let (result, record) = account_exists(Canned::failing("the proxy is down")).await;
        assert_matches!(result, Err(RequestError::Disconnected(_)));
        assert_eq!(cancelled(&record), &[] as &[u64]);
    }

    /// A requester that does what a real one does when the reply is slow: parks the thread
    /// `send` was called on, until `cancel` names the request it is parked on.
    ///
    /// [`Parked::GIVE_UP`] is what a real requester's own timeout would be. Nothing in the test
    /// waits that long -- it exists so that a seam which stopped delivering cancellation fails
    /// the assertions below and then lets the process exit, rather than leaving a blocking
    /// thread parked forever and hanging the whole run on the runtime's shutdown.
    struct Parked {
        shared: Arc<ParkedShared>,
    }

    impl Parked {
        const GIVE_UP: Duration = Duration::from_secs(20);
    }

    #[derive(Default)]
    struct ParkedShared {
        state: Mutex<ParkedState>,
        changed: std::sync::Condvar,
    }

    #[derive(Default)]
    struct ParkedState {
        in_flight: Option<u64>,
        cancelled: Vec<u64>,
        returned: bool,
    }

    impl ParkedShared {
        fn with<R>(&self, body: impl FnOnce(&ParkedState) -> R) -> R {
            body(&self.state.lock().expect("not poisoned"))
        }
    }

    impl ChatRequester for Parked {
        fn send(
            &self,
            request_id: u64,
            _method: String,
            _path: String,
            _headers: Box<[String]>,
            _body: Vec<u8>,
        ) -> Result<ChatRequesterResponse, std::io::Error> {
            let mut state = self.shared.state.lock().expect("not poisoned");
            state.in_flight = Some(request_id);
            self.shared.changed.notify_all();
            let (mut state, _) = self
                .shared
                .changed
                .wait_timeout_while(state, Self::GIVE_UP, |state| {
                    !state.cancelled.contains(&request_id)
                })
                .expect("not poisoned");
            state.returned = true;
            self.shared.changed.notify_all();
            // Discarded: whoever asked has gone. An error is what a torn-down request is.
            Err(std::io::Error::other("the caller let go"))
        }

        fn cancel(&self, request_id: u64) {
            let mut state = self.shared.state.lock().expect("not poisoned");
            state.cancelled.push(request_id);
            self.shared.changed.notify_all();
        }
    }

    /// Polls rather than blocks: this runs on the test's runtime thread, which is also the one
    /// that has to drop the abandoned future.
    async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    /// The whole of what the seam adds. A caller that goes away mid-request -- which is what
    /// libsignal's own cancellation does to the bridged future, dropping it -- reaches the
    /// requester as `cancel` naming the id `send` was given, and the parked call gets its
    /// thread back. Without that, both waits below expire: the blocking thread stays parked
    /// and the wire stays held until the app's own timeout, long after the caller was told
    /// the request was cancelled.
    #[tokio::test]
    async fn a_request_dropped_mid_flight_is_cancelled_by_id() {
        let shared = Arc::<ParkedShared>::default();
        let connection = UnauthenticatedChatConnection::with_requester(Box::new(Parked {
            shared: Arc::clone(&shared),
        }));
        let call = tokio::spawn(async move {
            connection
                .as_typed(|chat| chat.account_exists(ACI.into()))
                .await
        });

        eventually("the request to reach the requester", || {
            shared.with(|state| state.in_flight.is_some())
        })
        .await;
        let request_id = shared.with(|state| state.in_flight.expect("in flight"));

        call.abort();

        eventually("the requester to be told to let go", || {
            shared.with(|state| !state.cancelled.is_empty())
        })
        .await;
        assert_eq!(
            shared.with(|state| state.cancelled.clone()),
            vec![request_id],
            "cancelled the wrong request"
        );
        eventually("the parked call to return", || {
            shared.with(|state| state.returned)
        })
        .await;
    }

    #[tokio::test]
    async fn an_authenticated_connection_knows_its_own_aci() {
        let connection = AuthenticatedChatConnection::with_requester(
            Box::new(Canned::answering(200, &[], b"")),
            ACI,
        );
        let aci = connection
            .as_typed(|chat| Box::pin(async move { WsConnection::self_aci(&chat.0) }))
            .await;
        assert_eq!(aci, Some(ACI));
    }
}
