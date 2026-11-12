//
//  ContentView.swift
//  WQGuard
//
//  Root TabView container with dynamic badges and seamless navigation.
//

import SwiftUI
import WQGuardCore

public struct ContentView: View {
    @EnvironmentObject var vm: ScanViewModel

    public init() {}

    public var body: some View {
        TabView(selection: $vm.selectedTab) {
            NavigationStack {
                DashboardView()
            }
            .tabItem {
                Label(WQStrings.tabDashboard, systemImage: "shield.checkered")
            }
            .tag(0)

            NavigationStack {
                FindingsView()
            }
            .tabItem {
                Label(WQStrings.tabFindings, systemImage: "list.bullet.rectangle.portrait.fill")
            }
            .badge(vm.highRiskCount > 0 ? "\(vm.highRiskCount)" : nil)
            .tag(1)

            NavigationStack {
                IPAScanView()
            }
            .tabItem {
                Label(WQStrings.tabIPAScan, systemImage: "arrow.up.doc.fill")
            }
            .tag(2)

            NavigationStack {
                FirmwareRadarView()
            }
            .tabItem {
                Label(WQStrings.tabFirmwareRadar, systemImage: "antenna.radiowaves.left.and.right")
            }
            .badge(vm.firmwareReport.exposedCount > 0 ? "\(vm.firmwareReport.exposedCount)" : nil)
            .tag(3)

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label(WQStrings.tabSettings, systemImage: "gearshape.fill")
            }
            .tag(4)
        }
        .tint(Color(red: 0.0, green: 0.78, blue: 0.65)) // Security Teal
        .alert(
            WQStrings.alertScanTitle,
            isPresented: $vm.showGlobalAlert,
            actions: { Button(WQStrings.buttonOK, role: .cancel) {} },
            message: { Text(vm.activeAlertMessage ?? "") }
        )
    }
}
