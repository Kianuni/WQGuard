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
                    // Handle Share Sheet / Open-In from 全能签, ESign, Feather, Files, or AirDrop
                    let ext = url.pathExtension.lowercased()
                    if ext == "ipa" || ext == "tipa" || ext == "app" {
                        viewModel.scanIPAPackage(at: url)
                    }
                }
        }
    }
}
