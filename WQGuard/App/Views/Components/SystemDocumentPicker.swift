//
//  SystemDocumentPicker.swift
//  WQGuard
//
//  Direct UIKit topmost-controller presenter for `UIDocumentPickerViewController`.
//  Uses `asCopy: true` with `[.item, .data, .content]` for flat file imports
//  (.ipa, .tipa, .plist, .mobiledevicepairing, .json, .xml) so iOS never greys out
//  files across FileProviders and supports native multi-selection for `.ipa` packages.
//

import SwiftUI
import UniformTypeIdentifiers
#if canImport(UIKit)
import UIKit
#endif

public enum DocumentPickerKind: String, Identifiable {
    case ipaFiles
    case pairingFile
    case registrySnapshot

    public var id: String { rawValue }

    public var allowsMultipleSelection: Bool {
        self == .ipaFiles
    }
}

#if canImport(UIKit)
@MainActor
public final class NativeDocumentPickerPresenter: NSObject, UIDocumentPickerDelegate, UIAdaptivePresentationControllerDelegate {
    public static let shared = NativeDocumentPickerPresenter()

    private var retainedPicker: UIDocumentPickerViewController?
    private var onPickHandler: (([URL]) -> Void)?
    private var onCancelHandler: (() -> Void)?

    private override init() {
        super.init()
    }

    public func present(
        kind: DocumentPickerKind,
        onPick: @escaping ([URL]) -> Void,
        onCancel: @escaping () -> Void = {}
    ) {
        guard let hostVC = topMostViewController() else {
            onCancel()
            return
        }

        // `asCopy: true` + `[.item, .data, .content]` guarantees flat files (.ipa, .tipa,
        // .plist, .mobiledevicepairing, .json, .xml) are selectable across all FileProviders
        // without Open-In-Place restrictions, with multi-select enabled for `.ipaFiles`.
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: [.item, .data, .content],
            asCopy: true
        )
        picker.allowsMultipleSelection = kind.allowsMultipleSelection
        picker.shouldShowFileExtensions = true
        picker.delegate = self
        picker.presentationController?.delegate = self

        self.retainedPicker = picker
        self.onPickHandler = onPick
        self.onCancelHandler = onCancel

        hostVC.present(picker, animated: true)
    }

    public nonisolated func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        MainActor.assumeIsolated {
            let pick = self.onPickHandler
            let cancel = self.onCancelHandler
            self.clearRetainedState()
            guard !urls.isEmpty else {
                cancel?()
                return
            }

            // Persist `asCopy: true` temp inbox files synchronously before UIKit cleans up `-Inbox`
            let safeURLs = Self.stageCopiedFilesIfNeeded(urls)
            pick?(safeURLs)
        }
    }

    public nonisolated func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        MainActor.assumeIsolated {
            let cancel = self.onCancelHandler
            self.clearRetainedState()
            cancel?()
        }
    }

    public nonisolated func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        MainActor.assumeIsolated {
            let cancel = self.onCancelHandler
            self.clearRetainedState()
            cancel?()
        }
    }

    private func clearRetainedState() {
        self.retainedPicker = nil
        self.onPickHandler = nil
        self.onCancelHandler = nil
    }

    private static func stageCopiedFilesIfNeeded(_ urls: [URL]) -> [URL] {
        let fm = FileManager.default
        let stageDir = fm.temporaryDirectory.appendingPathComponent("WQGuardPicked", isDirectory: true)
        try? fm.createDirectory(at: stageDir, withIntermediateDirectories: true)

        return urls.map { src in
            let dst = stageDir.appendingPathComponent("\(UUID().uuidString.prefix(8))_\(src.lastPathComponent)")
            try? fm.removeItem(at: dst)
            if (try? fm.moveItem(at: src, to: dst)) != nil {
                return dst
            }
            if (try? fm.copyItem(at: src, to: dst)) != nil {
                return dst
            }
            return src
        }
    }

    private func topMostViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .filter { $0.activationState == .foregroundActive || $0.activationState == .foregroundInactive }

        let window = scenes.flatMap(\.windows).first(where: \.isKeyWindow)
            ?? scenes.flatMap(\.windows).first

        guard var top = window?.rootViewController else {
            return nil
        }
        while let presented = top.presentedViewController, !presented.isBeingDismissed {
            top = presented
        }
        return top
    }
}
#endif
