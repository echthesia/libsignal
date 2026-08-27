//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi
import XCTest

@testable import LibSignalClient

/// `Net` builds its tokio runtime and `ConnectionManager` on first use rather
/// than in `init` (a signal-watchos change; see the comment in `Net.swift`).
/// These check that the deferral is invisible: settings applied before first
/// use are in effect once the manager exists, and settings applied after go
/// straight through.
final class NetLazyConstructionTests: TestCaseBase {
    private static let userAgent = "test"

    // The proxy-state inspection this relies on isn't generated in device builds.
    #if !(os(iOS) || os(watchOS)) || targetEnvironment(simulator)

    func testConfigurationDoesNotRealize() throws {
        let net = Net(env: .staging, userAgent: Self.userAgent, buildVariant: .production)
        XCTAssertFalse(net.hasBeenUsed)

        net.setCensorshipCircumventionEnabled(true)
        net.setRemoteConfig(["key": "value"], buildVariant: .beta)
        net.clearProxy()
        net.setInvalidProxy()
        try net.networkDidChange()

        XCTAssertFalse(net.hasBeenUsed, "configuration alone must not build the runtime")
    }

    func testPendingSettingsAreReplayedOnFirstUse() {
        let net = Net(env: .staging, userAgent: Self.userAgent, buildVariant: .production)
        net.setInvalidProxy()

        // First use builds the manager with the recorded proxy state already applied.
        net.connectionManager.assertIsUsingProxyIs(-1)
        XCTAssertTrue(net.hasBeenUsed)

        // ...and later settings go straight through to it.
        net.clearProxy()
        net.connectionManager.assertIsUsingProxyIs(0)
        net.setInvalidProxy()
        net.connectionManager.assertIsUsingProxyIs(-1)
    }

    func testLastPendingProxySettingWins() {
        let net = Net(env: .staging, userAgent: Self.userAgent, buildVariant: .production)
        net.setInvalidProxy()
        net.clearProxy()
        net.connectionManager.assertIsUsingProxyIs(0)
    }

    func testSetProxyRealizesEagerly() throws {
        let net = Net(env: .staging, userAgent: Self.userAgent, buildVariant: .production)
        net.setInvalidProxy()
        try net.setProxy(host: "proxy.example", port: 443)
        XCTAssertTrue(net.hasBeenUsed, "setProxy validates against the real manager")
        net.connectionManager.assertIsUsingProxyIs(1)
    }

    func testRealizationIsIdempotentUnderContention() {
        let net = Net(env: .staging, userAgent: Self.userAgent, buildVariant: .production)
        net.setInvalidProxy()

        final class Seen: @unchecked Sendable {
            let lock = NSLock()
            var managers = Set<ObjectIdentifier>()
        }
        let seen = Seen()
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            let id = ObjectIdentifier(net.connectionManager)
            seen.lock.withLock { _ = seen.managers.insert(id) }
        }
        XCTAssertEqual(seen.managers.count, 1, "every first user must see the same manager")
        net.connectionManager.assertIsUsingProxyIs(-1)
    }

    #endif
}
