import Combine
import Foundation

@MainActor
final class ServerManager: ObservableObject {
    static let shared = ServerManager()

    enum ServerState: Equatable {
        case stopped
        case starting
        case running
        case failed(String)

        var label: String {
            switch self {
            case .stopped: return "Detenido"
            case .starting: return "Iniciando..."
            case .running: return "Activo"
            case .failed: return "Error"
            }
        }
    }

    @Published private(set) var state: ServerState = .stopped
    @Published private(set) var logs: [String] = []
    @Published private(set) var attachedToExisting = false

    let studioURL = URL(string: "http://127.0.0.1:8000/app")!
    let classicURL = URL(string: "http://127.0.0.1:8000/")!
    let healthURL = URL(string: "http://127.0.0.1:8000/health")!
    let scadaURL = URL(string: "http://127.0.0.1:8101")!
    let maintenanceURL = URL(string: "http://127.0.0.1:8102")!

    private var process: Process?
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?
    private var bootTask: Task<Void, Never>?
    private var intentionalStop = false

    private init() {}

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
        let uvCandidates = [
            "/Users/armandosilva/.local/bin/uv",
            "/opt/homebrew/bin/uv",
            "/usr/local/bin/uv",
        ]
        for candidate in uvCandidates where FileManager.default.isExecutableFile(atPath: candidate) {
            return (
                candidate,
                ["run", "python", "-m", "src.local_server", "--host", "127.0.0.1", "--port", "8000"]
            )
        }
        let venvPython = projectDir.appendingPathComponent(".venv/bin/python").path
        if FileManager.default.isExecutableFile(atPath: venvPython) {
            return (
                venvPython,
                ["-m", "src.local_server", "--host", "127.0.0.1", "--port", "8000"]
            )
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
        appendLog("[ControlBot.app] Verificando servidor local en http://127.0.0.1:8000...")

        bootTask = Task { [weak self] in
            guard let self else { return }
            if await self.checkHealth(timeout: 1.5) {
                self.attachedToExisting = true
                self.state = .running
                self.appendLog("[ControlBot.app] Servidor ControlBot ya activo; conectado sin duplicar procesos.")
                return
            }

            let projectDir = self.resolveProjectDirectory()
            guard let command = self.resolveCommand(projectDir: projectDir) else {
                self.state = .failed("No se encontró 'uv' ni '.venv/bin/python' en \(projectDir.path).")
                self.appendLog("[ERROR] Ejecutable uv/python no encontrado.")
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
                        self.appendLog("[ControlBot.app] Proceso terminado con código \(status).")
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
                self.appendLog("[ControlBot.app] Lanzado \(command.executable) \(command.arguments.joined(separator: " "))")
            } catch {
                self.cleanupPipes()
                self.state = .failed("No se pudo iniciar el servidor local: \(error.localizedDescription)")
                return
            }

            for _ in 0..<85 {
                if Task.isCancelled { return }
                if case .failed = self.state { return }
                if await self.checkHealth(timeout: 1.0) {
                    self.state = .running
                    self.appendLog("[ControlBot.app] Studio UX y laboratorios listos en http://127.0.0.1:8000/app")
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
            appendLog("[ControlBot.app] Deteniendo servidor local ControlBot...")
            proc.terminate()
        }
        cleanupPipes()
        process = nil
        attachedToExisting = false
        state = .stopped
    }

    func restart() {
        let wasAttached = attachedToExisting
        stop()
        if wasAttached {
            appendLog("[ControlBot.app] El servidor previo es externo; reintentando conexión...")
        }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 600_000_000)
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

    private func checkHealth(timeout: TimeInterval) async -> Bool {
        var req = URLRequest(url: healthURL)
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
