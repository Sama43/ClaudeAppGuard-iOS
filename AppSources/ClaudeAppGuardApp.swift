import SwiftUI

@main
struct ClaudeAppGuardApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var engine = VpnManagerEngine()
    @State private var selectedTab = 0

    var body: some Scene {
        WindowGroup {
            TabView(selection: $selectedTab) {
                ShieldDashboardView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("守护", systemImage: "shield.checkered") }
                    .tag(0)

                NodesView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("节点 (\(engine.nodes.count))", systemImage: "server.rack") }
                    .tag(1)

                SecurityView(engine: engine)
                    .tabItem { Label("审计", systemImage: "lock.doc.fill") }
                    .tag(2)
            }
            .onChange(of: scenePhase, initial: true) { _, phase in engine.setForeground(phase == .active) }
            .tint(VpnTheme.accentTeal)
            .preferredColorScheme(.dark)
        }
    }
}
