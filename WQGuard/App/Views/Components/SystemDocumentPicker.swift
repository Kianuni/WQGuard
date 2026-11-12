//
//  SystemDocumentPicker.swift
//  WQGuard
//
//  Direct UIKit topmost-controller presenter for `UIDocumentPickerViewController`.
//  - Uses `asCopy: true` with `[.item, .data, .content]` for file imports (.plist,
//    .mobiledevicepairing, .json, .xml, .ipa) so iOS NEVER greys out files due to
//    Open-In-Place provider or CFBundleTypeRole restrictions.
//  - Uses `UIDocumentPickerViewController(forOpeningContentTypes: [.folder])` with
//    `allowsMultipleSelection = false` for signing folder binding.
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

    public var isFolderSelection: Bool {
        self == .signingFolder
    }

    public var allowsMultipleSelection: Bool {
        self == .ipaFiles
    }
}

#if canImport(UIKit)
@MainActor
public final class NativeDocumentPickerPresenter: NSObject, UIDocumentPickerDelegate, UIAdaptivePresentationControllerDelegate {
    public static let shared = NativeDocumentPickerPresenter()

    private var retainedPicker: UIDocumentPickerViewController?
    private var activeKind: DocumentPickerKind = .pairingFile
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

        let picker: UIDocumentPickerViewController
        switch kind {
        case .signingFolder:
            // Explicit `asCopy: false` directory open-in-place mode (works for On My iPhone user folders,
            // iCloud Drive, and apps declaring `LSSupportsOpeningDocumentsInPlace = true`).
            picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder], asCopy: false)
        case .ipaFiles:
            // `asCopy: true` with `.applicationBundle` + `.package` + `.item` allows selecting BOTH `.ipa`/`.tipa`
            // archives AND unpacked `.app` bundles inside `Feather -> Signed -> <UUID>/` even when the host signer
            // app (`Feather`) omits `LSSupportsOpeningDocumentsInPlace`!
            picker = UIDocumentPickerViewController(
                forOpeningContentTypes: [.applicationBundle, .package, .bundle, .item, .data, .content],
                asCopy: true
            )
        case .pairingFile, .registrySnapshot:
            // `asCopy: true` + `[.item, .data, .content]` enables ALL `.plist`, `.mobiledevicepairing`,
            // `.json`, and `.xml` files across every FileProvider without greying out.
            picker = UIDocumentPickerViewController(
                forOpeningContentTypes: [.item, .data, .content],
                asCopy: true
            )
        }
        picker.allowsMultipleSelection = kind.allowsMultipleSelection
        picker.shouldShowFileExtensions = true
        picker.delegate = self
        picker.presentationController?.delegate = self

        self.activeKind = kind
        self.retainedPicker = picker
        self.onPickHandler = onPick
        self.onCancelHandler = onCancel

        hostVC.present(picker, animated: true)
    }

    public nonisolated func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        MainActor.assumeIsolated {
            let pick = self.onPickHandler
            let cancel = self.onCancelHandler
            let isFolder = self.activeKind.isFolderSelection
            self.clearRetainedState()
            guard !urls.isEmpty else {
                cancel?()
                return
            }

            if isFolder {
                pick?(urls)
            } else {
                // Persist `asCopy: true` temp inbox files synchronously before UIKit cleans up `-Inbox`
                let safeURLs = Self.stageCopiedFilesIfNeeded(urls)
                pick?(safeURLs)
            }
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
