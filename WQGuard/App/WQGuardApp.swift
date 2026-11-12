//
//  WQGuardApp.swift
//  WQGuard
//
//  Entry point for standalone WQGuard iOS Application.
//

import SwiftUI
import WQGuardCore

@main
struct WQGuardApp: App {
    @StateObject private var viewModel = ScanViewModel.shared
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
                .preferredColorScheme(.dark)
                .onOpenURL { url in
                    // Handle Share Sheet / Open-In for .ipa, .tipa, .mobiledevicepairing, .plist, .xml, .json
                    viewModel.handleIncomingURL(url)
                }
                .onChange(of: scenePhase) { newPhase in
                    if newPhase == .active {
                        viewModel.autoImportFromDocumentsFolderIfNeeded()
                    }
                }
        }
    }
}
