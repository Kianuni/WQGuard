//
//  TerminalCodeView.swift
//  WQGuard
//
//  Monospace code and report viewer with dark background and copy support.
//

import SwiftUI

public struct TerminalCodeView: View {
    public let text: String

    public init(text: String) {
        self.text = text
    }

    public var body: some View {
        ScrollView([.horizontal, .vertical]) {
            Text(text)
                .font(.system(size: 11, weight: .regular, design: .monospaced))
                .foregroundColor(Color(red: 0.85, green: 0.90, blue: 0.95))
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(red: 0.05, green: 0.06, blue: 0.08))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.white.opacity(0.1), lineWidth: 1)
        )
    }
}
