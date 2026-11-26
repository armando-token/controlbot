import Combine
import Foundation

@MainActor
final class ServerManager: ObservableObject {
    static let shared = ServerManager()

    enum ConnectionMode: String, CaseIterable, Identifiable {
        case local
        case remote

        var id: String { rawValue }
        var label: String {
            switch self {
            case .local: return "Local (esta Mac)"
            case .remote: return "Remoto (Mac mini servidor)"
            }
        }
    }

    enum ServerState: Equatable {
        case stopped
        case starting
        case running
        case failed(String)

        var label: String {
            switch self {
            case .stopped: return "Detenido"
            case .starting: return "Conectando..."
            case .running: return "Activo"
            case .failed: return "Error"
            }
        }
    }

    private enum DefaultsKey {
        static let connectionMode = "controlbot.connectionMode"
        static let remoteBaseURL = "controlbot.remoteBaseURL"
        static let enablePlantLab = "controlbot.enablePlantLab"
    }

    @Published private(set) var state: ServerState = .stopped
    @Published private(set) var logs: [String] = []
    @Published private(set) var attachedToExisting = false
    @Published var connectionMode: ConnectionMode
    @Published var remoteBaseURLString: String
    @Published var enablePlantLab: Bool

    var activeBaseURL: URL {
        if connectionMode == .remote,
           let parsed = Self.normalizeBaseURL(remoteBaseURLString) {
            return parsed
        }
        return URL(string: "http://127.0.0.1:8000")!
    }

    var studioURL: URL { activeBaseURL.appendingPathComponent("app") }
    var classicURL: URL { activeBaseURL }
    var healthURL: URL { activeBaseURL.appendingPathComponent("health") }
    let scadaURL = URL(string: "http://127.0.0.1:8101")!
    let maintenanceURL = URL(string: "http://127.0.0.1:8102")!

    private var process: Process?
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?
    private var bootTask: Task<Void, Never>?
    private var intentionalStop = false

    private init() {
        let defaults = UserDefaults.standard
        let rawMode = defaults.string(forKey: DefaultsKey.connectionMode) ?? "local"
        self.connectionMode = ConnectionMode(rawValue: rawMode) ?? .local
        self.remoteBaseURLString =
            defaults.string(forKey: DefaultsKey.remoteBaseURL)
            ?? "http://Armandos-Mac-mini.local:8000"
        self.enablePlantLab = defaults.bool(forKey: DefaultsKey.enablePlantLab)
    }

    static func normalizeBaseURL(_ raw: String) -> URL? {
        var trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if !trimmed.contains("://") {
            trimmed = "http://\(trimmed)"
        }
        while trimmed.hasSuffix("/") {
            trimmed.removeLast()
        }
        guard let url = URL(string: trimmed), let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https", url.host != nil else {
            return nil
        }
        return url
    }

    func applyConnectionSettings(mode: ConnectionMode, remoteURL: String, enablePlantLab: Bool) {
        let defaults = UserDefaults.standard
        defaults.set(mode.rawValue, forKey: DefaultsKey.connectionMode)
        defaults.set(remoteURL.trimmingCharacters(in: .whitespacesAndNewlines), forKey: DefaultsKey.remoteBaseURL)
        defaults.set(enablePlantLab, forKey: DefaultsKey.enablePlantLab)

        stop()
        self.connectionMode = mode
        self.remoteBaseURLString = remoteURL.trimmingCharacters(in: .whitespacesAndNewlines)
        self.enablePlantLab = enablePlantLab
        start()
    }

    func resolveProjectDirectory() -> URL {
        if let envDir = ProcessInfo.processInfo.environment["CONTROLBOT_PROJECT_DIR"],
           !envDir.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let candidate = URL(fileURLWithPath: envDir)
            if FileManager.default.fileExists(atPath: candidate.appendingPathComponent("src/local_server.py").path) {
                return candidate
            }
        }

        let defaultPath = URL(fileURLWithPath: "/Users/armandosilva/Projects/Grokbotclon")
        if FileManager.default.fileExists(atPath: defaultPath.appendingPathComponent("src/local_server.py").path) {
            return defaultPath
        }

        var cursor = Bundle.main.bundleURL
        for _ in 0..<8 {
            cursor = cursor.deletingLastPathComponent()
            if FileManager.default.fileExists(atPath: cursor.appendingPathComponent("src/local_server.py").path) {
                return cursor
            }
        }
        return defaultPath
    }

    private func resolveCommand(projectDir: URL) -> (executable: String, arguments: [String])? {
        var pythonArgs = ["-m", "src.local_server", "--host", "127.0.0.1", "--port", "8000"]
        if !enablePlantLab {
            pythonArgs.append("--no-lab")
        }
        let uvCandidates = [
            "/Users/armandosilva/.local/bin/uv",
            "/opt/homebrew/bin/uv",
            "/usr/local/bin/uv",
        ]
        for candidate in uvCandidates where FileManager.default.isExecutableFile(atPath: candidate) {
            return (candidate, ["run", "python"] + pythonArgs)
        }
        let venvPython = projectDir.appendingPathComponent(".venv/bin/python").path
        if FileManager.default.isExecutableFile(atPath: venvPython) {
            return (venvPython, pythonArgs)
        }
        return nil
    }

    func appendLog(_ line: String) {
        let trimmed = line.trimmingCharacters(in: .newlines)
        guard !trimmed.isEmpty else { return }
        logs.append(trimmed)
        if logs.count > 400 {
            logs.removeFirst(logs.count - 400)
        }
    }

    func clearLogs() {
        logs.removeAll()
    }

    func ensureStarted() {
        if case .running = state { return }
        if case .starting = state { return }
        start()
    }

    func start() {
        bootTask?.cancel()
        intentionalStop = false
        attachedToExisting = false
        state = .starting

        let targetHealth = healthURL
        let targetStudio = studioURL
        appendLog("[ControlBot.app] Conectando con \(activeBaseURL.absoluteString)...")

        if connectionMode == .remote {
            attachedToExisting = true
            bootTask = Task { [weak self] in
                guard let self else { return }
                for _ in 0..<8 {
                    if Task.isCancelled { return }
                    if await self.checkHealth(url: targetHealth, timeout: 2.0) {
                        self.state = .running
                        self.appendLog("[ControlBot.app] Conectado al servidor remoto: \(targetStudio.absoluteString)")
                        return
                    }
                    try? await Task.sleep(nanoseconds: 400_000_000)
                }
                self.state = .failed(
                    "No se pudo conectar con \(self.activeBaseURL.absoluteString). "
                    + "Verifica que el servicio esté activo en tu Mac mini (--lan o túnel SSH)."
                )
            }
            return
        }

        bootTask = Task { [weak self] in
            guard let self else { return }
            if await self.checkHealth(url: targetHealth, timeout: 1.5) {
                self.attachedToExisting = true
                self.state = .running
                self.appendLog("[ControlBot.app] Adjuntado al servidor headless ya activo en 127.0.0.1:8000.")
                return
            }

            let projectDir = self.resolveProjectDirectory()
            guard let command = self.resolveCommand(projectDir: projectDir) else {
                self.state = .failed(
                    "No se encontró el proyecto local en \(projectDir.path). "
                    + "Si estás en tu otra MacBook, cambia Conexión a 'Remoto'."
                )
                return
            }

            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: command.executable)
            proc.arguments = command.arguments
            proc.currentDirectoryURL = projectDir

            var env = ProcessInfo.processInfo.environment
            let extraPath = "/Users/armandosilva/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
            env["PATH"] = env["PATH"].map { "\(extraPath):\($0)" } ?? extraPath
            env["PYTHONUNBUFFERED"] = "1"
            proc.environment = env

            let outPipe = Pipe()
            let errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe

            outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
                Task { @MainActor [weak self] in
                    for line in text.components(separatedBy: .newlines) {
                        self?.appendLog(line)
                    }
                }
            }
            errPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
                Task { @MainActor [weak self] in
                    for line in text.components(separatedBy: .newlines) {
                        self?.appendLog(line)
                    }
                }
            }

            proc.terminationHandler = { [weak self] ended in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.cleanupPipes()
                    let status = ended.terminationStatus
                    if self.process === ended {
                        self.process = nil
                    }
                    if !self.intentionalStop {
                        self.state = .failed("El servidor local finalizó inesperadamente (código \(status)).")
                    } else if case .starting = self.state {
                        self.state = .stopped
                    }
                }
            }

            do {
                try proc.run()
                self.process = proc
                self.stdoutPipe = outPipe
                self.stderrPipe = errPipe
                self.appendLog("[ControlBot.app] Servidor local iniciado (\(self.enablePlantLab ? "con lab" : "modo ligero --no-lab"))")
            } catch {
                self.cleanupPipes()
                self.state = .failed("No se pudo iniciar el servidor local: \(error.localizedDescription)")
                return
            }

            for _ in 0..<85 {
                if Task.isCancelled { return }
                if case .failed = self.state { return }
                if await self.checkHealth(url: targetHealth, timeout: 1.0) {
                    self.state = .running
                    self.appendLog("[ControlBot.app] Studio listo en \(targetStudio.absoluteString)")
                    return
                }
                try? await Task.sleep(nanoseconds: 300_000_000)
            }

            if case .starting = self.state {
                self.state = .failed("Tiempo de espera agotado al iniciar ControlBot en el puerto 8000.")
            }
        }
    }

    func stop() {
        bootTask?.cancel()
        bootTask = nil
        intentionalStop = true
        if let proc = process, proc.isRunning, !attachedToExisting {
            appendLog("[ControlBot.app] Deteniendo servidor local...")
            proc.terminate()
        }
        cleanupPipes()
        process = nil
        attachedToExisting = false
        state = .stopped
    }

    func restart() {
        stop()
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 500_000_000)
            self?.start()
        }
    }

    func terminateIfOwned() {
        bootTask?.cancel()
        bootTask = nil
        intentionalStop = true
        if let proc = process, proc.isRunning, !attachedToExisting {
            proc.terminate()
            let deadline = Date().addingTimeInterval(2.0)
            while proc.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if proc.isRunning {
                kill(proc.processIdentifier, SIGKILL)
            }
        }
        cleanupPipes()
        process = nil
    }

    private func cleanupPipes() {
        stdoutPipe?.fileHandleForReading.readabilityHandler = nil
        stderrPipe?.fileHandleForReading.readabilityHandler = nil
        stdoutPipe = nil
        stderrPipe = nil
    }

    private func checkHealth(url: URL, timeout: TimeInterval) async -> Bool {
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            if let http = response as? HTTPURLResponse {
                return http.statusCode == 200
            }
            return false
        } catch {
            return false
        }
    }
}
