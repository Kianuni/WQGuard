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

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
                .preferredColorScheme(.dark)
                .onOpenURL { url in
                    // Handle AirDrop or Open In for .ipa files
                    if url.pathExtension.lowercased() == "ipa" {
                        viewModel.scanIPAPackage(at: url)
                    }
                }
        }
    }
}
