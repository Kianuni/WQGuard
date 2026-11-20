//
//  SystemDocumentPicker.swift
//  WQGuard
//
//  Direct UIKit topmost-controller presenter for `UIDocumentPickerViewController`.
//  Uses `asCopy: true` with `[.item, .data, .content]` for flat file imports
//  (.ipa, .tipa, .plist, .mobiledevicepairing, .json, .xml) so iOS never greys out
//  files across FileProviders and supports native multi-selection for `.ipa` packages.
//

import Darwin
import SwiftUI
import UniformTypeIdentifiers
import WQGuardCore
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
    private var isStagingInFlight: Bool = false

    private override init() {
        super.init()
    }

    public func present(
        kind: DocumentPickerKind,
        onPick: @escaping ([URL]) -> Void,
        onCancel: @escaping () -> Void = {}
    ) {
        // Reject overlapping/concurrent presentations without clobbering active handlers.
        guard !isStagingInFlight,
              retainedPicker == nil,
              onPickHandler == nil else {
            onCancel()
            return
        }
        guard let hostVC = topMostViewController(),
              !(hostVC is UIDocumentPickerViewController),
              hostVC.presentedViewController == nil else {
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
            guard controller === self.retainedPicker else { return }
            let pick = self.onPickHandler
            let cancel = self.onCancelHandler
            self.clearRetainedState()
            guard !urls.isEmpty else {
                cancel?()
                return
            }

            // Pin FDs / rename synchronously while UIKit `-Inbox` exists, then stream large copies off @MainActor.
            self.isStagingInFlight = true
            let workItems = Self.prepareStagingWorkItems(urls)
            Task { @MainActor [weak self] in
                let stagedURLs = await Task.detached(priority: .userInitiated) {
                    Self.executeStagingWorkItems(workItems)
                }.value
                self?.isStagingInFlight = false
                pick?(stagedURLs)
            }
        }
    }

    public nonisolated func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        MainActor.assumeIsolated {
            guard controller === self.retainedPicker else { return }
            let cancel = self.onCancelHandler
            self.clearRetainedState()
            cancel?()
        }
    }

    public nonisolated func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        MainActor.assumeIsolated {
            guard presentationController.presentedViewController === self.retainedPicker else { return }
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

    public nonisolated static func cleanupPickedStagingFileIfApplicable(_ url: URL) {
        guard url.deletingLastPathComponent().lastPathComponent == "WQGuardPicked" else { return }
        _ = Darwin.unlink(IPAPackageScanner.stripTrailingSlashes(url.path))
    }

    private nonisolated enum StageWorkItem: Sendable {
        case alreadyStaged(URL)
        case fallback(URL)
        case pinned(originalURL: URL, destinationURL: URL, sourceFD: Int32, cleanupInboxURL: URL?)
    }

    private nonisolated static func sanitizePickedFilename(_ rawName: String, maxUTF8Bytes: Int = 230) -> String? {
        var filteredScalars: [UnicodeScalar] = []
        filteredScalars.reserveCapacity(rawName.unicodeScalars.count)
        for scalar in rawName.unicodeScalars {
            let v = scalar.value
            if v <= 0x1F || v == 0x7F || v == 0x2F || v == 0x5C {
                continue
            }
            filteredScalars.append(scalar)
        }
        var clean = String(String.UnicodeScalarView(filteredScalars))
        while clean.hasPrefix(".") {
            clean.removeFirst()
        }
        guard !clean.isEmpty, clean != ".", clean != ".." else {
            return nil
        }
        if clean.utf8.count <= maxUTF8Bytes {
            return clean
        }

        // Preserve extension while truncating stem cleanly at UTF-8 Character boundaries + deterministic hash
        let nsClean = clean as NSString
        let rawExt = nsClean.pathExtension
        let extSuffix = (!rawExt.isEmpty && rawExt.utf8.count <= 30) ? ".\(rawExt)" : ""
        let stem = extSuffix.isEmpty ? clean : nsClean.deletingPathExtension

        var fnv: UInt32 = 2166136261
        for byte in clean.utf8 {
            fnv ^= UInt32(byte)
            fnv = fnv &* 16777619
        }
        let hashTag = String(format: "_%08x", fnv)
        let maxStemBytes = max(1, maxUTF8Bytes - extSuffix.utf8.count - hashTag.utf8.count)

        var truncatedStem = ""
        var usedBytes = 0
        for ch in stem {
            let chBytes = String(ch).utf8.count
            if usedBytes + chBytes > maxStemBytes { break }
            truncatedStem.append(ch)
            usedBytes += chBytes
        }
        let result = "\(truncatedStem)\(hashTag)\(extSuffix)"
        guard !result.isEmpty, result != ".", result != "..", result.utf8.count <= maxUTF8Bytes else {
            return nil
        }
        return result
    }

    private static func prepareStagingWorkItems(_ urls: [URL]) -> [StageWorkItem] {
        let fm = FileManager.default
        let stageDir = fm.temporaryDirectory.appendingPathComponent("WQGuardPicked", isDirectory: true)
        let cleanStageDir = IPAPackageScanner.stripTrailingSlashes(stageDir.path)
        var dirSt = stat()
        if lstat(cleanStageDir, &dirSt) == 0, (dirSt.st_mode & S_IFMT) == S_IFLNK {
            try? fm.removeItem(at: stageDir)
        }
        try? fm.createDirectory(at: stageDir, withIntermediateDirectories: true)

        // Purge abandoned staging files older than 10 minutes
        if let stale = try? fm.contentsOfDirectory(at: stageDir, includingPropertiesForKeys: nil, options: []) {
            let nowSec = time(nil)
            for item in stale {
                var itemSt = stat()
                let p = IPAPackageScanner.stripTrailingSlashes(item.path)
                if lstat(p, &itemSt) == 0, nowSec - itemSt.st_mtimespec.tv_sec > 600 {
                    _ = Darwin.unlink(p)
                }
            }
        }

        let maxBytes: off_t = 1024 * 1024 * 1024
        let rawTmp = fm.temporaryDirectory.resolvingSymlinksInPath().path
        let tmpPrefix = IPAPackageScanner.stripTrailingSlashes(rawTmp)

        return urls.map { src in
            guard let sanitizedName = sanitizePickedFilename(src.lastPathComponent, maxUTF8Bytes: 230) else {
                return .fallback(src)
            }
            let cleanSrcPath = IPAPackageScanner.stripTrailingSlashes(src.path)
            var srcSt = stat()
            guard lstat(cleanSrcPath, &srcSt) == 0,
                  (srcSt.st_mode & S_IFMT) == S_IFREG,
                  srcSt.st_size >= 0,
                  srcSt.st_size <= maxBytes else {
                return .fallback(src)
            }

            let dst = stageDir.appendingPathComponent("\(UUID().uuidString.prefix(8))_\(sanitizedName)")
            let cleanDstPath = IPAPackageScanner.stripTrailingSlashes(dst.path)

            let srcParent = IPAPackageScanner.stripTrailingSlashes(
                src.deletingLastPathComponent().resolvingSymlinksInPath().path
            )
            let isTempInbox = !tmpPrefix.isEmpty
                && (srcParent == tmpPrefix || srcParent.hasPrefix(tmpPrefix + "/"))

            if isTempInbox, Darwin.rename(cleanSrcPath, cleanDstPath) == 0 {
                return .alreadyStaged(dst)
            }

            let inFD = Darwin.open(cleanSrcPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard inFD >= 0 else {
                return .fallback(src)
            }
            var fdSt = stat()
            guard fstat(inFD, &fdSt) == 0,
                  (fdSt.st_mode & S_IFMT) == S_IFREG,
                  fdSt.st_size >= 0,
                  fdSt.st_size <= maxBytes else {
                Darwin.close(inFD)
                return .fallback(src)
            }

            return .pinned(
                originalURL: src,
                destinationURL: dst,
                sourceFD: inFD,
                cleanupInboxURL: isTempInbox ? src : nil
            )
        }
    }

    private nonisolated static func executeStagingWorkItems(_ items: [StageWorkItem]) -> [URL] {
        let maxBytes: Int64 = 1024 * 1024 * 1024
        let chunkSize = 1024 * 1024

        return items.map { item in
            switch item {
            case .alreadyStaged(let dst):
                return dst
            case .fallback(let src):
                return src
            case .pinned(let originalURL, let destinationURL, let sourceFD, let cleanupInboxURL):
                defer { Darwin.close(sourceFD) }

                let cleanDstPath = IPAPackageScanner.stripTrailingSlashes(destinationURL.path)
                let tmpDstPath = cleanDstPath + ".tmp.\(UUID().uuidString.prefix(8))"
                let outFD = Darwin.open(tmpDstPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
                guard outFD >= 0 else {
                    return originalURL
                }

                var buffer = [UInt8](repeating: 0, count: chunkSize)
                var totalWritten: Int64 = 0
                var copySucceeded = true

                while true {
                    let bytesRead = buffer.withUnsafeMutableBytes { ptr in
                        Darwin.read(sourceFD, ptr.baseAddress, ptr.count)
                    }
                    if bytesRead == 0 {
                        break
                    }
                    if bytesRead < 0 {
                        if errno == EINTR || errno == EAGAIN { continue }
                        copySucceeded = false
                        break
                    }
                    if totalWritten + Int64(bytesRead) > maxBytes {
                        copySucceeded = false
                        break
                    }

                    var offset = 0
                    while offset < bytesRead {
                        let written = buffer.withUnsafeBytes { ptr in
                            Darwin.write(outFD, ptr.baseAddress!.advanced(by: offset), bytesRead - offset)
                        }
                        if written < 0 {
                            if errno == EINTR || errno == EAGAIN { continue }
                            copySucceeded = false
                            break
                        }
                        offset += written
                    }
                    if !copySucceeded { break }
                    totalWritten += Int64(bytesRead)
                }

                Darwin.close(outFD)
                guard copySucceeded, Darwin.rename(tmpDstPath, cleanDstPath) == 0 else {
                    _ = Darwin.unlink(tmpDstPath)
                    return originalURL
                }

                if let inboxURL = cleanupInboxURL {
                    _ = Darwin.unlink(IPAPackageScanner.stripTrailingSlashes(inboxURL.path))
                }
                return destinationURL
            }
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
