//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// The wire for a chat connection that has no websocket.
///
/// Every typed service on ``UnauthenticatedChatConnection`` and ``AuthenticatedChatConnection``
/// is, underneath, one HTTP-shaped request and one HTTP-shaped response; the websocket is only
/// how they usually travel. A process that cannot hold a websocket supplies a `ChatRequester`
/// instead, through ``Net/unauthenticatedChatConnection(requester:)`` and
/// ``Net/authenticatedChatConnection(requester:username:)``, and the services run over it
/// unchanged: libsignal still builds each request (headers included), decodes each response, and
/// maps each failure. What the requester does is carry bytes.
///
/// `send` is synchronous by contract. libsignal calls it from a thread that exists to be blocked,
/// never from the caller's, and continues when it returns. A thrown error means the request never
/// reached the server or the reply never came back; it surfaces to the caller as a transport
/// failure, which callers treat as retryable, and only its existence crosses the bridge, so a
/// requester logs what went wrong before throwing. A reply the server did send, whatever its
/// status, is a ``ChatResponse``, so that each service's own status handling (rate limits,
/// mismatched devices, rejections) applies to it. Forward every response header as received: the
/// decoders read `Content-Type` and `Retry-After`, and a reply with no body must arrive with no
/// content type.
///
/// Because `send` blocks, the only way a caller who has given up can reach it is from outside:
/// each request carries a ``ChatRequestCancellation``, and libsignal fires it when the caller's
/// task is cancelled while that request is still in flight. A requester that ignores it is still
/// correct -- it just keeps a request on the wire, and a thread blocked on it, after nobody is
/// waiting for the answer. What it returns after that is discarded.
///
/// A connection that is authenticated at the socket sends no `Authorization` per request, so a
/// requester standing in for an authenticated connection adds it.
///
/// The gRPC-backed services (backups, devices, account settings, the authenticated username
/// calls) need the websocket's HTTP/2 companion and are not available over a requester.
public protocol ChatRequester: AnyObject, Sendable {
    func send(_ request: ChatRequesterRequest) throws -> ChatResponse
}

/// One HTTP-shaped request for a ``ChatRequester`` to carry.
///
/// Deliberately not ``ChatRequest``, which is what ``ChatConnection``'s own `send` takes: that
/// one carries a `timeout` the connection applies per request, and over a requester there is no
/// such number to carry. The typed services send with no deadline at all
/// (`rust/net/chat/src/ws.rs` passes `Duration::MAX`), so how long to wait is the requester's
/// own decision, and ``cancellation`` is how it hears that waiting has stopped being useful.
public struct ChatRequesterRequest: Sendable {
    public let method: String
    public let pathAndQuery: String
    /// Everything libsignal would have sent down the socket for this request -- the content
    /// type, the unidentified access key or group-send token of a sealed send. The requester
    /// adds whatever its own transport needs on top.
    public let headers: [String: String]
    /// `nil` for a request without a body, which is not the same as an empty one: a GET
    /// carrying even two bytes is refused outright by some proxies.
    public let body: Data?
    /// Fires when the caller of this request has gone away. See ``ChatRequestCancellation``.
    public let cancellation: ChatRequestCancellation

    public init(
        method: String,
        pathAndQuery: String,
        headers: [String: String] = [:],
        body: Data? = nil,
        cancellation: ChatRequestCancellation
    ) {
        self.method = method
        self.pathAndQuery = pathAndQuery
        self.headers = headers
        self.body = body
        self.cancellation = cancellation
    }
}

/// What a ``ChatRequester`` hooks its own cancellation to.
///
/// libsignal fires this when the caller's `Task` is cancelled -- or the awaited future is
/// otherwise dropped -- while the request it belongs to is still inside `send`. It can happen on
/// any thread, including the one blocked in `send`, and it happens at most once per request;
/// after `send` has returned it never happens at all. A cancellation that arrives before `send`
/// is entered is not lost: ``onCancel(_:)`` fires its handler at once in that case.
///
/// Firing it does not make `send` return. It is a message to the requester, whose job is to stop
/// waiting -- tear the request down, throw, and let the thread go.
public final class ChatRequestCancellation: @unchecked Sendable {
    // Not `Sendable` outright: the two pieces of state below are mutable and read from whichever
    // thread fires or observes the cancellation, so the lock is what makes this safe rather than
    // the type system.
    private let lock = NSLock()
    private var cancelled = false
    private var handler: (@Sendable () -> Void)?

    public init() {}

    public var isCancelled: Bool {
        self.lock.withLock { self.cancelled }
    }

    /// Runs `handler` when this request is cancelled, or at once if it already has.
    ///
    /// One handler: a second call replaces the first, which has no waiting caller of its own to
    /// disappoint. The handler runs outside the lock, so it may do anything, including read
    /// ``isCancelled``.
    public func onCancel(_ handler: @escaping @Sendable () -> Void) {
        let fireNow = self.lock.withLock { () -> Bool in
            if self.cancelled {
                return true
            }
            self.handler = handler
            return false
        }
        if fireNow {
            handler()
        }
    }

    /// Fires the handler, once, outside the lock. Called from the bridge below.
    internal func cancel() {
        let handler = self.lock.withLock { () -> (@Sendable () -> Void)? in
            if self.cancelled {
                return nil
            }
            self.cancelled = true
            defer { self.handler = nil }
            return self.handler
        }
        handler?()
    }
}

extension Net {
    /// An unauthenticated chat connection whose wire is `requester`.
    ///
    /// Usable at once: there is nothing to connect and no listener to start. The connection
    /// owns the requester for as long as it lives.
    public func unauthenticatedChatConnection(
        requester: any ChatRequester
    ) throws -> UnauthenticatedChatConnection {
        let handle = try ChatRequesterBridge(requester).withRequesterStruct { requesterStruct in
            try invokeFnReturningValueByPointer(SignalMutPointerUnauthenticatedChatConnection()) {
                signal_unauthenticated_chat_connection_new_with_requester($0, requesterStruct)
            }
        }
        return UnauthenticatedChatConnection(
            fakeHandle: NonNull(handle)!,
            tokioAsyncContext: self.asyncContext,
            environment: self.environment
        )
    }

    /// An authenticated chat connection whose wire is `requester`, for the account whose HTTP
    /// auth username is `username` (`{aci}` or `{aci}.{deviceId}`, exactly as
    /// ``connectAuthenticatedChat(username:password:receiveStories:languages:)`` takes it).
    ///
    /// The socket would have authenticated once, at connect time; over a requester the
    /// credentials go on each request, and putting them there is the requester's job. The
    /// username is kept so the services that address the account itself know who that is.
    public func authenticatedChatConnection(
        requester: any ChatRequester,
        username: String
    ) throws -> AuthenticatedChatConnection {
        let handle = try ChatRequesterBridge(requester).withRequesterStruct { requesterStruct in
            try invokeFnReturningValueByPointer(SignalMutPointerAuthenticatedChatConnection()) {
                signal_authenticated_chat_connection_new_with_requester($0, requesterStruct, username)
            }
        }
        return AuthenticatedChatConnection(
            fakeHandle: NonNull(handle)!,
            tokioAsyncContext: self.asyncContext
        )
    }
}

/// Holds a ``ChatRequester`` across the bridge.
///
/// Rust clones the C struct into the connection and calls `destroy` when the connection is
/// dropped, so the bridge retains itself for the struct's lifetime and lets go in `destroy`.
/// The callbacks are `@convention(c)` and capture nothing; the bridge travels as `ctx`.
///
/// The two callbacks meet here. `send` runs on a thread Rust means to block; `cancel` names a
/// request id and can arrive on any thread while that `send` is still running -- so the request
/// ids in flight, and the cancellation each one belongs to, are kept in a table under a lock.
internal final class ChatRequesterBridge: @unchecked Sendable {
    private let requester: any ChatRequester
    private let lock = NSLock()
    private var inFlight: [UInt64: ChatRequestCancellation] = [:]
    /// Ids `cancel` named before their `send` had started.
    ///
    /// Rust arms the cancellation before handing the call to its blocking pool, and a blocking
    /// call that is still queued runs anyway once its handle is dropped -- so on a busy pool the
    /// cancellation gets here first. Remembering it is what keeps that `send` from putting a
    /// request nobody wants on the wire. Each id is taken out again by the `send` it was waiting
    /// for. What would stay is a `cancel` that landed after its `send` had returned but before
    /// Rust saw it return, or an id whose blocking call never ran because the runtime went away;
    /// neither can be told from a not-yet-started `send` at the time it arrives, so the set is
    /// capped instead and forgets its oldest ids. Ids are handed out in order by the connection
    /// this bridge belongs to, so the smallest is the oldest, and a request that far behind is
    /// not still waiting to start. (The order `send`s *start* in is the blocking pool's, not the
    /// ids', so the highest id started says nothing about which lower ones are still queued.)
    private var cancelledBeforeSend: Set<UInt64> = []
    private static let cancelledBeforeSendCapacity = 64

    init(_ requester: any ChatRequester) {
        self.requester = requester
    }

    /// The cancellation for `requestId`, already fired if `cancel` got here first.
    private func beginRequest(_ requestId: UInt64) -> ChatRequestCancellation {
        let cancellation = ChatRequestCancellation()
        let alreadyCancelled = self.lock.withLock { () -> Bool in
            self.inFlight[requestId] = cancellation
            return self.cancelledBeforeSend.remove(requestId) != nil
        }
        if alreadyCancelled {
            cancellation.cancel()
        }
        return cancellation
    }

    private func endRequest(_ requestId: UInt64) {
        self.lock.withLock { _ = self.inFlight.removeValue(forKey: requestId) }
    }

    /// Fires `requestId`'s cancellation, outside the lock.
    ///
    /// Nothing in flight under that id means either a `send` that has yet to start, which must
    /// find the cancellation waiting for it, or one that has already returned, where there is
    /// nothing left to reach. They cannot be told apart here, so the id is remembered either
    /// way and the table's cap is what keeps the second kind from accumulating.
    private func cancelRequest(_ requestId: UInt64) {
        let cancellation = self.lock.withLock { () -> ChatRequestCancellation? in
            if let cancellation = self.inFlight[requestId] {
                return cancellation
            }
            self.cancelledBeforeSend.insert(requestId)
            if self.cancelledBeforeSend.count > Self.cancelledBeforeSendCapacity,
                let oldest = self.cancelledBeforeSend.min()
            {
                self.cancelledBeforeSend.remove(oldest)
            }
            return nil
        }
        cancellation?.cancel()
    }

    /// Runs `body` with a struct that names this bridge, retained once for Rust to release.
    func withRequesterStruct<Result>(
        _ body: (SignalConstPointerFfiChatRequesterStruct) throws -> Result
    ) rethrows -> Result {
        var requesterStruct = SignalFfiChatRequesterStruct(
            ctx: Unmanaged.passRetained(self).toOpaque(),
            send: { rawCtx, out, requestId, method, path, headers, body in
                let bridge = Unmanaged<ChatRequesterBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
                let request = ChatRequesterRequest(
                    method: String(cString: method!),
                    pathAndQuery: String(cString: path!),
                    headers: ChatRequesterBridge.headers(consuming: headers),
                    body: ChatRequesterBridge.body(consuming: body),
                    cancellation: bridge.beginRequest(requestId)
                )
                defer { bridge.endRequest(requestId) }
                signal_free_string(method)
                signal_free_string(path)
                do {
                    let response = try bridge.requester.send(request)
                    out!.pointee = try ChatRequesterBridge.handle(for: response)
                    return 0
                } catch {
                    // A cancelled request throwing is the cancellation working, not a fault, so
                    // it is not reported as one; the error itself is discarded either way.
                    LoggerBridge.shared?.logger.log(
                        level: request.cancellation.isCancelled ? .info : .warn,
                        file: #fileID,
                        line: #line,
                        message: "chat requester failed: \(error)"
                    )
                    return -1
                }
            },
            cancel: { rawCtx, requestId in
                let bridge = Unmanaged<ChatRequesterBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
                bridge.cancelRequest(requestId)
                return 0
            },
            destroy: { rawCtx in
                Unmanaged<ChatRequesterBridge>.fromOpaque(rawCtx!).release()
            }
        )
        return try withUnsafePointer(to: &requesterStruct) {
            try body(SignalConstPointerFfiChatRequesterStruct(raw: $0))
        }
    }

    /// `Name: value` lines, as Rust wrote them, into the dictionary ``ChatRequest`` carries.
    private static func headers(consuming array: SignalBytestringArray) -> [String: String] {
        var bytes = UnsafeBufferPointer(start: array.bytes.base, count: array.bytes.length)[...]
        let lengths = UnsafeBufferPointer(start: array.lengths.base, count: array.lengths.length)
        var headers: [String: String] = [:]
        for length in lengths {
            let line = String(decoding: UnsafeBufferPointer(rebasing: bytes.prefix(length)), as: UTF8.self)
            bytes = bytes.dropFirst(length)
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon])
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        signal_free_bytestring_array(array)
        return headers
    }

    private static func body(consuming buffer: SignalOwnedBuffer) -> Data? {
        let data = Data(consuming: buffer)
        return data.isEmpty ? nil : data
    }

    /// The response as Rust reads it: status, every header as a `Name: value` line, the body.
    private static func handle(for response: ChatResponse) throws -> SignalMutPointerChatRequesterResponse {
        let headerLines = response.headers.map { "\($0.key): \($0.value)" }
        return try headerLines.withUnsafeBorrowedBytestringArray { headers in
            try response.body.withUnsafeBorrowedBuffer { body in
                try invokeFnReturningValueByPointer(SignalMutPointerChatRequesterResponse()) {
                    signal_chat_requester_response_new($0, UInt32(response.status), headers, body)
                }
            }
        }
    }
}
