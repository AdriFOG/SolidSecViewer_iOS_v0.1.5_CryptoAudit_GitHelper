import Foundation
import UniformTypeIdentifiers

extension UTType {
    static let nikaidoExplorerItems = UTType(exportedAs: "com.teamnikaido.explorer-items")
}

struct ExplorerDragPayload: Codable {
    let urls: [String]
    let sourcePane: Int

    func itemProvider() -> NSItemProvider {
        let provider = NSItemProvider()
        provider.registerDataRepresentation(
            forTypeIdentifier: UTType.nikaidoExplorerItems.identifier,
            visibility: .all
        ) { completion in
            do {
                completion(try JSONEncoder().encode(self), nil)
            } catch {
                completion(nil, error)
            }
            return nil
        }
        return provider
    }

    static func load(from providers: [NSItemProvider]) async throws -> ExplorerDragPayload {
        guard let provider = providers.first(where: {
            $0.hasItemConformingToTypeIdentifier(UTType.nikaidoExplorerItems.identifier)
        }) else {
            throw ExplorerOperationError.operationFailed("El elemento arrastrado no pertenece a Nikaido Explorer.")
        }

        return try await withCheckedThrowingContinuation { continuation in
            provider.loadDataRepresentation(forTypeIdentifier: UTType.nikaidoExplorerItems.identifier) { data, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let data else {
                    continuation.resume(throwing: ExplorerOperationError.operationFailed("No se pudo leer el arrastre."))
                    return
                }
                do {
                    continuation.resume(returning: try JSONDecoder().decode(Self.self, from: data))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
