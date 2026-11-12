//
//  SystemDocumentPicker.swift
//  WQGuard
//
//  Direct UIKit `UIDocumentPickerViewController` wrapper avoiding SwiftUI multiple
//  `.fileImporter` modifier conflicts on iOS 26/27 and capturing security-scoped
//  resources synchronously inside the delegate callback.
//

import SwiftUI
import UniformTypeIdentifiers
#if canImport(UIKit)
import UIKit
#endif

public enum DocumentPickerKind: String, Identifiable {
    case signingFolder
    case ipaFiles
    case pairingFile
    case registrySnapshot

    public var id: String { rawValue }

    public var contentTypes: [UTType] {
        switch self {
        case .signingFolder:
            return [.folder]
        case .ipaFiles, .pairingFile, .registrySnapshot:
            return [.data, .item]
        }
    }

    public var allowsMultipleSelection: Bool {
        switch self {
        case .ipaFiles, .signingFolder:
            return true
        case .pairingFile, .registrySnapshot:
            return false
        }
    }
}

#if canImport(UIKit)
public struct SystemDocumentPicker: UIViewControllerRepresentable {
    public let kind: DocumentPickerKind
    public let onPick: ([URL]) -> Void
    public let onCancel: () -> Void

    public init(
        kind: DocumentPickerKind,
        onPick: @escaping ([URL]) -> Void,
        onCancel: @escaping () -> Void = {}
    ) {
        self.kind = kind
        self.onPick = onPick
        self.onCancel = onCancel
    }

    public func makeCoordinator() -> Coordinator {
        Coordinator(onPick: onPick, onCancel: onCancel)
    }

    public func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: kind.contentTypes,
            asCopy: false
        )
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = kind.allowsMultipleSelection
        picker.shouldShowFileExtensions = true
        return picker
    }

    public func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    public final class Coordinator: NSObject, UIDocumentPickerDelegate {
        private let onPick: ([URL]) -> Void
        private let onCancel: () -> Void

        init(onPick: @escaping ([URL]) -> Void, onCancel: @escaping () -> Void) {
            self.onPick = onPick
            self.onCancel = onCancel
        }

        public func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard !urls.isEmpty else {
                onCancel()
                return
            }
            onPick(urls)
        }

        public func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            onCancel()
        }
    }
}
#endif
