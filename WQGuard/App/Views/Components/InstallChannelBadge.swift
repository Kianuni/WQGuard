//
//  InstallChannelBadge.swift
//  WQGuard
//
//  Visual badge displaying the app distribution channel.
//

import SwiftUI
import WQGuardCore

public struct InstallChannelBadge: View {
    public let channel: InstallChannel

    public init(channel: InstallChannel) {
        self.channel = channel
    }

    public var body: some View {
        Text(WQStrings.channelName(channel))
            .font(.system(size: 10, weight: .semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.white.opacity(0.08))
            .foregroundColor(.gray)
            .clipShape(Capsule())
    }
}
