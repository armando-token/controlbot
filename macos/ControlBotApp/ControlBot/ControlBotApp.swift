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
    @State private var showConnectionPopover = false
    @State private var draftMode: ServerManager.ConnectionMode = .local
    @State private var draftRemoteURL = ""
    @State private var draftPlantLab = false

    private let lightBg = Color(red: 0.973, green: 0.980, blue: 0.988)
    private let lightCard = Color.white

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
                        Text("Conectando con ControlBot...")
                            .font(.title2.weight(.semibold))
                            .foregroundStyle(.primary)
                        Text(server.connectionMode == .remote
                             ? "Conectando a \(server.activeBaseURL.absoluteString)"
                             : "Iniciando servidor ligero en 127.0.0.1:8000")
                            .foregroundStyle(.secondary)
                        logPreviewCard
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(32)
                    .background(lightBg)
                case .failed(let message):
                    VStack(spacing: 14) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 36))
                            .foregroundStyle(.red)
                        Text("No se pudo conectar a ControlBot")
                            .font(.title2.weight(.semibold))
                        Text(message)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .frame(maxWidth: 560)
                        logPreviewCard
                        HStack(spacing: 12) {
                            Button("Reintentar") {
                                server.start()
                            }
                            .buttonStyle(.borderedProminent)
                            Button("Cambiar conexión...") {
                                syncDraftFromServer()
                                showConnectionPopover = true
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(32)
                    .background(lightBg)
                }
            }

            if showLogs {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Logs de conexión / servidor")
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
                .background(lightCard)
            }
        }
        .onAppear {
            syncDraftFromServer()
            server.ensureStarted()
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                    Text("\(server.state.label) · \(server.connectionMode == .remote ? "Remoto" : "Local")")
                        .font(.caption.weight(.semibold))
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(.quaternary.opacity(0.35), in: Capsule())
            }

            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    syncDraftFromServer()
                    showConnectionPopover.toggle()
                } label: {
                    Label("Conexión", systemImage: "network")
                }
                .help("Configurar servidor Local o Remoto (Mac mini)")
                .popover(isPresented: $showConnectionPopover, arrowEdge: .top) {
                    connectionPopover
                }

                Button {
                    reloadToken = UUID()
                } label: {
                    Label("Recargar", systemImage: "arrow.clockwise")
                }
                .help("Recargar Studio")

                Button {
                    server.restart()
                } label: {
                    Label("Reconectar", systemImage: "arrow.triangle.2.circlepath")
                }
                .help("Reiniciar conexión o servidor")

                Button {
                    showLogs.toggle()
                } label: {
                    Label("Logs", systemImage: "terminal")
                }
                .help("Mostrar u ocultar logs")

                Menu {
                    Button("Abrir Studio en navegador (/app)") {
                        NSWorkspace.shared.open(server.studioURL)
                    }
                    Button("Abrir Consola Clásica (/)") {
                        NSWorkspace.shared.open(server.classicURL)
                    }
                    Menu("Demo Planta") {
                        Button("Portal SCADA (8101)") {
                            NSWorkspace.shared.open(server.scadaURL)
                        }
                        Button("Portal Maintenance (8102)") {
                            NSWorkspace.shared.open(server.maintenanceURL)
                        }
                    }
                } label: {
                    Label("Más", systemImage: "ellipsis.circle")
                }
            }
        }
    }

    private func syncDraftFromServer() {
        draftMode = server.connectionMode
        draftRemoteURL = server.remoteBaseURLString
        draftPlantLab = server.enablePlantLab
    }

    private var connectionPopover: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Conexión de ControlBot")
                .font(.headline)

            Picker("Modo", selection: $draftMode) {
                ForEach(ServerManager.ConnectionMode.allCases) { mode in
                    Text(mode.label).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            if draftMode == .remote {
                VStack(alignment: .leading, spacing: 4) {
                    Text("URL del servidor Mac mini")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    TextField("http://Armandos-Mac-mini.local:8000", text: $draftRemoteURL)
                        .textFieldStyle(.roundedBorder)
                    Text("Usa http://Armandos-Mac-mini.local:8000 en Wi-Fi (--lan) o http://127.0.0.1:8000 con túnel SSH.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else {
                Toggle("Iniciar portales Demo Planta (8101–8103)", isOn: $draftPlantLab)
                    .font(.caption)
            }

            HStack {
                Spacer()
                Button("Cancelar") {
                    showConnectionPopover = false
                }
                Button("Conectar") {
                    server.applyConnectionSettings(
                        mode: draftMode,
                        remoteURL: draftRemoteURL,
                        enablePlantLab: draftPlantLab
                    )
                    showConnectionPopover = false
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(16)
        .frame(width: 340)
        .preferredColorScheme(.light)
    }

    private var logPreviewCard: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 3) {
                ForEach(Array(server.logs.suffix(10).enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(10)
        }
        .frame(maxWidth: 680, maxHeight: 160)
        .background(lightCard, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.gray.opacity(0.25), lineWidth: 1))
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
                .preferredColorScheme(.light)
        }
        .defaultSize(width: 1320, height: 840)

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
            Button("Reconectar") {
                server.restart()
            }
            Divider()
            Button("Salir de ControlBot") {
                NSApp.terminate(nil)
            }
        }
    }
}
