import Foundation
import Combine
import SwiftUI

@MainActor
final class ExplorerOperationQueue: ObservableObject {
    enum Kind: String, Sendable {
        case copy = "Copiar"
        case move = "Mover"
        case trash = "Papelera"
        case restore = "Restaurar"
    }

    enum State: Equatable {
        case queued
        case running
        case completed
        case failed(String)
        case cancelled
    }

    struct Job: Identifiable {
        let id: UUID
        let title: String
        let kind: Kind
        var state: State
        var completedUnits: Int
        let totalUnits: Int
    }

    @Published private(set) var jobs: [Job] = []
    @Published private(set) var isRunning = false

    private var pending: [(UUID, @MainActor () async throws -> Void)] = []
    private var worker: Task<Void, Never>?

    var activeCount: Int {
        jobs.filter {
            if case .queued = $0.state { return true }
            if case .running = $0.state { return true }
            return false
        }.count
    }

    func enqueue(
        title: String,
        kind: Kind,
        totalUnits: Int = 1,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        let id = UUID()
        jobs.insert(
            Job(
                id: id,
                title: title,
                kind: kind,
                state: .queued,
                completedUnits: 0,
                totalUnits: max(totalUnits, 1)
            ),
            at: 0
        )
        pending.append((id, operation))
        startWorkerIfNeeded()
    }

    func cancelQueued(_ id: UUID) {
        pending.removeAll { $0.0 == id }
        update(id) { $0.state = .cancelled }
    }

    func clearFinished() {
        jobs.removeAll {
            switch $0.state {
            case .completed, .failed, .cancelled:
                return true
            case .queued, .running:
                return false
            }
        }
    }

    private func startWorkerIfNeeded() {
        guard worker == nil else { return }
        worker = Task { [weak self] in
            guard let self else { return }
            await self.runLoop()
        }
    }

    private func runLoop() async {
        isRunning = true
        defer {
            isRunning = false
            worker = nil
        }

        while !pending.isEmpty {
            let (id, operation) = pending.removeFirst()
            update(id) { $0.state = .running }

            do {
                try Task.checkCancellation()
                try await operation()
                update(id) {
                    $0.completedUnits = $0.totalUnits
                    $0.state = .completed
                }
            } catch is CancellationError {
                update(id) { $0.state = .cancelled }
            } catch {
                update(id) { $0.state = .failed(error.localizedDescription) }
            }
        }
    }

    private func update(_ id: UUID, _ body: (inout Job) -> Void) {
        guard let index = jobs.firstIndex(where: { $0.id == id }) else { return }
        body(&jobs[index])
    }
}

struct ExplorerOperationQueueView: View {
    @ObservedObject var queue: ExplorerOperationQueue

    var body: some View {
        NavigationStack {
            List {
                if queue.jobs.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "list.bullet.rectangle")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("Sin operaciones").font(.headline)
                        Text("Las copias, movimientos y restauraciones aparecerán aquí.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 30)
                }

                ForEach(queue.jobs) { job in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(job.title)
                                .lineLimit(2)
                            Spacer()
                            stateView(job.state)
                        }
                        Text(job.kind.rawValue)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .swipeActions {
                        if case .queued = job.state {
                            Button("Cancelar", role: .destructive) {
                                queue.cancelQueued(job.id)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Operaciones")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Limpiar") {
                        queue.clearFinished()
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func stateView(_ state: ExplorerOperationQueue.State) -> some View {
        switch state {
        case .queued:
            Label("En cola", systemImage: "clock")
                .font(.caption)
                .foregroundStyle(.secondary)
        case .running:
            ProgressView().controlSize(.small)
        case .completed:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .cancelled:
            Image(systemName: "xmark.circle")
                .foregroundStyle(.secondary)
        case .failed:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        }
    }
}
