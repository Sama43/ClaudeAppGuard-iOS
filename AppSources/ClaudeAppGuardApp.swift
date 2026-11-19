import SwiftUI

@main
struct ClaudeAppGuardApp: App {
    @StateObject private var engine = VpnManagerEngine()
    @State private var selectedTab = 0

    var body: some Scene {
        WindowGroup {
            TabView(selection: $selectedTab) {
                ShieldDashboardView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("守护", systemImage: "shield.checkered") }
                    .tag(0)

                SessionsView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("身份 (\(engine.sessions.count))", systemImage: "person.badge.shield.checkmark.fill") }
                    .tag(1)

                NodesView(engine: engine, selectedTab: $selectedTab)
                    .tabItem { Label("节点 (\(engine.nodes.count))", systemImage: "server.rack") }
                    .tag(2)

                SecurityView(engine: engine)
                    .tabItem { Label("审计", systemImage: "lock.doc.fill") }
                    .tag(3)
            }
            .tint(VpnTheme.accentTeal)
            .preferredColorScheme(.dark)
        }
    }
}
