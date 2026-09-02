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
/// A connection that is authenticated at the socket sends no `Authorization` per request, so a
/// requester standing in for an authenticated connection adds it.
///
/// The gRPC-backed services (backups, devices, account settings, the authenticated username
/// calls) need the websocket's HTTP/2 companion and are not available over a requester.
public protocol ChatRequester: AnyObject, Sendable {
    func send(_ request: ChatRequest) throws -> ChatResponse
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
internal final class ChatRequesterBridge: @unchecked Sendable {
    private let requester: any ChatRequester

    init(_ requester: any ChatRequester) {
        self.requester = requester
    }

    /// Runs `body` with a struct that names this bridge, retained once for Rust to release.
    func withRequesterStruct<Result>(
        _ body: (SignalConstPointerFfiChatRequesterStruct) throws -> Result
    ) rethrows -> Result {
        var requesterStruct = SignalFfiChatRequesterStruct(
            ctx: Unmanaged.passRetained(self).toOpaque(),
            send: { rawCtx, out, method, path, headers, body in
                let bridge = Unmanaged<ChatRequesterBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
                let request = ChatRequest(
                    method: String(cString: method!),
                    pathAndQuery: String(cString: path!),
                    headers: ChatRequesterBridge.headers(consuming: headers),
                    body: ChatRequesterBridge.body(consuming: body),
                    timeout: 0
                )
                signal_free_string(method)
                signal_free_string(path)
                do {
                    let response = try bridge.requester.send(request)
                    out!.pointee = try ChatRequesterBridge.handle(for: response)
                    return 0
                } catch {
                    LoggerBridge.shared?.logger.log(
                        level: .warn,
                        file: #fileID,
                        line: #line,
                        message: "chat requester failed: \(error)"
                    )
                    return -1
                }
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
