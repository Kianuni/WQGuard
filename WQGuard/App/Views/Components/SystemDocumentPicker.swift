//
//  SystemDocumentPicker.swift
//  WQGuard
//
//  Direct UIKit topmost-controller presenter for `UIDocumentPickerViewController`.
//  Eliminates SwiftUI `.fileImporter` / `.sheet` lifecycle & double-dismissal bugs
//  on iOS 26/27, enforces `allowsMultipleSelection = false` for `.folder` mode so
//  the top-right "打开" (Open) button activates immediately, and strongly retains
//  both picker and delegate until completion.
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
            // Must be strictly [.folder] with allowsMultipleSelection = false
            // so iOS Files activates the top-right "打开" button for the current directory.
            return [.folder]
        case .pairingFile:
            return [.propertyList, .xml, .data, .content, .item]
        case .registrySnapshot:
            return [.propertyList, .xml, .json, .plainText, .data, .content, .item]
        case .ipaFiles:
            return [.data, .archive, .zip, .content, .item]
        }
    }

    public var allowsMultipleSelection: Bool {
        switch self {
        case .ipaFiles:
            return true
        case .signingFolder, .pairingFile, .registrySnapshot:
            return false
        }
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

        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: kind.contentTypes,
            asCopy: false
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
            pick?(urls)
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
