import AppKit
import SwiftUI

final class ControlBotAppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated {
            ServerManager.shared.terminateIfOwned()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

struct ContentView: View {
    @ObservedObject var server = ServerManager.shared
    @State private var reloadToken = UUID()
    @State private var showLogs = false

    private var statusColor: Color {
        switch server.state {
        case .running: return .green
        case .starting: return .orange
        case .stopped: return .gray
        case .failed: return .red
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch server.state {
                case .running:
                    ControlBotWebView(url: server.studioURL, reloadToken: reloadToken)
                case .starting, .stopped:
                    VStack(spacing: 16) {
                        ProgressView()
                            .controlSize(.large)
                        Text("Iniciando ControlBot local...")
                            .font(.title2.weight(.semibold))
                        Text("Levantando SCADA (8101), Maintenance (8102), EffectSim (8103) y Studio UX (8000)")
                            .foregroundStyle(.secondary)
                        logPreviewCard
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(32)
                    .background(Color(red: 0.043, green: 0.059, blue: 0.090))
                case .failed(let message):
                    VStack(spacing: 14) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 36))
                            .foregroundStyle(.red)
                        Text("No se pudo iniciar ControlBot")
                            .font(.title2.weight(.semibold))
                        Text(message)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 560)
                        logPreviewCard
                        Button("Reintentar") {
                            server.start()
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(32)
                    .background(Color(red: 0.043, green: 0.059, blue: 0.090))
                }
            }

            if showLogs {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Logs del servidor local")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Limpiar") {
                            server.clearLogs()
                        }
                        .buttonStyle(.borderless)
                        .font(.caption)
                    }
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(server.logs.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
                .padding(10)
                .frame(height: 170)
                .background(Color(red: 0.067, green: 0.094, blue: 0.153))
            }
        }
        .onAppear {
            server.ensureStarted()
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                    Text(server.state.label)
                        .font(.caption.weight(.semibold))
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(.quaternary.opacity(0.4), in: Capsule())
            }

            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    reloadToken = UUID()
                } label: {
                    Label("Recargar", systemImage: "arrow.clockwise")
                }
                .help("Recargar Studio UX")

                Button {
                    server.restart()
                } label: {
                    Label("Reiniciar servidor", systemImage: "arrow.triangle.2.circlepath")
                }
                .help("Reiniciar servidor local ControlBot")

                Button {
                    showLogs.toggle()
                } label: {
                    Label("Logs", systemImage: "terminal")
                }
                .help("Mostrar u ocultar logs del servidor")

                Menu {
                    Button("Abrir Studio en navegador (/app)") {
                        NSWorkspace.shared.open(server.studioURL)
                    }
                    Button("Abrir Consola Clásica (/)") {
                        NSWorkspace.shared.open(server.classicURL)
                    }
                    Divider()
                    Button("Portal SCADA (8101)") {
                        NSWorkspace.shared.open(server.scadaURL)
                    }
                    Button("Portal Maintenance (8102)") {
                        NSWorkspace.shared.open(server.maintenanceURL)
                    }
                } label: {
                    Label("Portales", systemImage: "safari")
                }
            }
        }
    }

    private var logPreviewCard: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 3) {
                ForEach(Array(server.logs.suffix(12).enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(10)
        }
        .frame(maxWidth: 680, maxHeight: 170)
        .background(Color(red: 0.067, green: 0.094, blue: 0.153), in: RoundedRectangle(cornerRadius: 10))
    }
}

@main
struct ControlBotApp: App {
    @NSApplicationDelegateAdaptor(ControlBotAppDelegate.self) var appDelegate
    @ObservedObject private var server = ServerManager.shared
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        WindowGroup("ControlBot", id: "main") {
            ContentView()
                .preferredColorScheme(.dark)
        }
        .defaultSize(width: 1360, height: 860)

        MenuBarExtra("ControlBot", systemImage: "cpu") {
            Text("Estado: \(server.state.label)")
            Divider()
            Button("Abrir ventana ControlBot") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            Button("Abrir Studio en navegador") {
                NSWorkspace.shared.open(server.studioURL)
            }
            Button("Reiniciar servidor local") {
                server.restart()
            }
            Divider()
            Button("Salir de ControlBot") {
                NSApp.terminate(nil)
            }
        }
    }
}
