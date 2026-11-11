//
//  InjectedDylibsView.swift
//  WQGuard
//
//  Inspector view listing embedded, linked, and potentially injected dynamic libraries.
//

import SwiftUI
import WQGuardCore

public struct InjectedDylibsView: View {
    public let dylibs: [String]

    public init(dylibs: [String]) {
        self.dylibs = dylibs
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "puzzlepiece.extension.fill")
                    .foregroundColor(.teal)
                Text(WQStrings.injectedDylibsTitle(dylibs.count))
                    .font(.headline)
                    .foregroundColor(.white)
            }

            if dylibs.isEmpty {
                Text(WQStrings.injectedDylibsEmpty)
                    .font(.caption)
                    .foregroundColor(.gray)
            } else {
                ForEach(dylibs, id: \.self) { dylib in
                    HStack {
                        Image(systemName: isSuspicious(dylib) ? "exclamationmark.triangle.fill" : "checkmark.seal")
                            .foregroundColor(isSuspicious(dylib) ? .orange : .gray)
                            .font(.caption)

                        Text(dylib)
                            .font(.caption.monospaced())
                            .foregroundColor(isSuspicious(dylib) ? .orange : .white.opacity(0.85))
                            .lineLimit(1)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(red: 0.10, green: 0.11, blue: 0.15))
        )
    }

    private func isSuspicious(_ path: String) -> Bool {
        let lower = path.lowercased()
        return lower.contains("cydia") || lower.contains("substitute") || lower.contains("substrate") || lower.contains("hook") || lower.contains("tweak") || lower.contains("shadow") || lower.contains("inject")
    }
}
