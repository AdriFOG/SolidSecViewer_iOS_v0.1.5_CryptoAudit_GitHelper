import Foundation

enum ExplorerStorageKind: String, Codable, Sendable {
    case local
    case authorized
}

struct ExplorerStorageLocation: Identifiable, Equatable, Sendable {
    let id: UUID
    let name: String
    let rootURL: URL
    let kind: ExplorerStorageKind
    let isPersistentReference: Bool

    static func == (
        lhs: ExplorerStorageLocation,
        rhs: ExplorerStorageLocation
    ) -> Bool {
        lhs.id == rhs.id &&
        lhs.rootURL.standardizedFileURL == rhs.rootURL.standardizedFileURL
    }
}

struct ExplorerFileItem: Identifiable, Hashable, Sendable {
    let url: URL
    let name: String
    let isDirectory: Bool
    let isHidden: Bool
    let size: Int64?
    let modifiedAt: Date?
    let typeIdentifier: String?

    var id: String {
        url.standardizedFileURL.path
    }

    var pathExtension: String {
        url.pathExtension.lowercased()
    }

    var isArchive: Bool {
        ["zip", "7z", "rar"].contains(pathExtension)
    }

    var systemImage: String {
        if isDirectory {
            return "folder.fill"
        }

        switch pathExtension {
        case "zip", "7z", "rar":
            return "archivebox.fill"
        case "jpg", "jpeg", "png", "gif", "webp", "heic", "heif":
            return "photo.fill"
        case "mp4", "mov", "m4v", "mkv", "avi", "webm", "3gp":
            return "film.fill"
        case "mp3", "m4a", "aac", "wav", "flac", "ogg":
            return "waveform"
        case "pdf":
            return "doc.richtext.fill"
        case "txt", "md", "json", "xml", "log", "csv":
            return "doc.text.fill"
        default:
            return "doc.fill"
        }
    }

    var formattedSize: String {
        guard !isDirectory, let size else {
            return ""
        }

        return ByteCountFormatter.string(
            fromByteCount: size,
            countStyle: .file
        )
    }
}

enum ExplorerViewMode: String, CaseIterable, Identifiable {
    case list
    case grid

    var id: String { rawValue }

    var title: String {
        switch self {
        case .list:
            return "Lista"
        case .grid:
            return "Cuadrícula"
        }
    }

    var systemImage: String {
        switch self {
        case .list:
            return "list.bullet"
        case .grid:
            return "square.grid.2x2"
        }
    }
}

enum ExplorerSortMode: String, CaseIterable, Identifiable, Sendable {
    case name
    case date
    case size
    case kind

    var id: String { rawValue }

    var title: String {
        switch self {
        case .name:
            return "Nombre"
        case .date:
            return "Fecha"
        case .size:
            return "Tamaño"
        case .kind:
            return "Tipo"
        }
    }
}

enum ExplorerConflictPolicy: String, CaseIterable, Identifiable, Sendable {
    case rename
    case replace

    var id: String { rawValue }

    var title: String {
        switch self {
        case .rename:
            return "Conservar ambos"
        case .replace:
            return "Reemplazar"
        }
    }
}

enum ExplorerOperationError: Error, LocalizedError {
    case noLocation
    case outsideAuthorizedRoot
    case invalidName
    case destinationInsideSource
    case unsupportedArchive
    case archiveTooLargeForInMemory7z
    case unsafeArchivePath(String)
    case tooManyArchiveEntries
    case insufficientStorage(required: Int64, available: Int64)
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .noLocation:
            return "No hay una ubicación abierta."
        case .outsideAuthorizedRoot:
            return "La operación intentó salir de la raíz autorizada."
        case .invalidName:
            return "El nombre no es válido."
        case .destinationInsideSource:
            return "No puedes mover o copiar una carpeta dentro de sí misma."
        case .unsupportedArchive:
            return "Este formato de archivo comprimido todavía no es compatible."
        case .archiveTooLargeForInMemory7z:
            return "Este 7z es demasiado grande para el extractor actual. "
                + "La compatibilidad 7z de esta versión usa memoria y limita "
                + "el archivo comprimido para evitar que iOS cierre la app."
        case .unsafeArchivePath(let path):
            return "El archivo comprimido contiene una ruta insegura: \(path)"
        case .tooManyArchiveEntries:
            return "El archivo comprimido contiene demasiados elementos."
        case .insufficientStorage(let required, let available):
            return "No hay espacio suficiente. Se requieren aproximadamente "
                + "\(ByteCountFormatter.string(fromByteCount: required, countStyle: .file)) "
                + "y hay \(ByteCountFormatter.string(fromByteCount: available, countStyle: .file))."
        case .operationFailed(let message):
            return message
        }
    }
}
