import SwiftUI
import UIKit
import UniformTypeIdentifiers

private enum ExplorerPendingAction {
    case rename(ExplorerFileItem, pane: Int)
    case delete([ExplorerFileItem], pane: Int)
    case extract(ExplorerFileItem, pane: Int)
}

struct ExplorerView: View {
    let onOpenVault: () -> Void
    let onOpenSecReader: () -> Void

    @StateObject private var locations = SecurityScopedFolderStore()
    @StateObject private var favorites = ExplorerFavoritesStore()
    @StateObject private var leftPane = ExplorerPaneState()
    @StateObject private var rightPane = ExplorerPaneState()
    @StateObject private var operationQueue = ExplorerOperationQueue()
    @StateObject private var trash = ExplorerTrashManager()

    @State private var activePane = 0
    @State private var showFolderPicker = false
    @State private var showStorageLocations = false
    @State private var showSettings = false
    @State private var showOperations = false
    @State private var showTrash = false
    @State private var showSMB = false
    @State private var showNewFolder = false
    @State private var newFolderName = ""
    @State private var renameText = ""
    @State private var pendingAction: ExplorerPendingAction?
    @State private var previewTarget: ExplorerPreviewTarget?
    @State private var shareURLs: [URL] = []
    @State private var showShareSheet = false
    @State private var archivePassword = ""
    @State private var globalError: String?
    @State private var isOperating = false

    @AppStorage("NikaidoExplorer.conflictPolicy")
    private var conflictPolicyRaw = ExplorerConflictPolicy.rename.rawValue

    @AppStorage("NikaidoExplorer.confirmDelete")
    private var confirmDelete = true

    private var conflictPolicy: ExplorerConflictPolicy {
        ExplorerConflictPolicy(rawValue: conflictPolicyRaw) ?? .rename
    }

    private var active: ExplorerPaneState {
        activePane == 0 ? leftPane : rightPane
    }

    private var other: ExplorerPaneState {
        activePane == 0 ? rightPane : leftPane
    }

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                explorerTopBar

                Divider()

                if proxy.size.width >= 700 {
                    HStack(spacing: 0) {
                        paneView(
                            leftPane,
                            index: 0
                        )

                        Divider()

                        paneView(
                            rightPane,
                            index: 1
                        )
                    }
                } else {
                    Picker(
                        "Panel",
                        selection: $activePane
                    ) {
                        Text("Panel 1").tag(0)
                        Text("Panel 2").tag(1)
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)

                    paneView(
                        activePane == 0 ? leftPane : rightPane,
                        index: activePane
                    )
                }

                if active.selectionMode {
                    Divider()
                    selectionToolbar
                }
            }
            .background(Color(uiColor: .systemBackground))
        }
        .navigationBarHidden(true)
        .sheet(isPresented: $showFolderPicker) {
            ExplorerFolderPicker { url in
                if let location = locations.addAuthorizedFolder(url) {
                    active.openLocation(location)
                } else if let message = locations.lastError {
                    globalError = message
                }
            }
        }
        .sheet(isPresented: $showStorageLocations) {
            ExplorerStorageLocationsView(
                locations: locations,
                favorites: favorites,
                leftPane: leftPane,
                rightPane: rightPane,
                activePane: $activePane
            ) {
                showStorageLocations = false

                DispatchQueue.main.async {
                    showFolderPicker = true
                }
            }
        }
        .sheet(isPresented: $showSettings) {
            ExplorerSettingsView(
                conflictPolicyRaw: $conflictPolicyRaw,
                confirmDelete: $confirmDelete
            )
        }
        .sheet(isPresented: $showOperations) {
            ExplorerOperationQueueView(queue: operationQueue)
        }
        .sheet(isPresented: $showTrash) {
            ExplorerTrashView(trash: trash) {
                Task {
                    await leftPane.refresh()
                    await rightPane.refresh()
                }
            }
        }
        .sheet(isPresented: $showSMB) {
            ExplorerSMBView(
                destinationDirectory: active.currentURL,
                uploadItems: active.selectedItems,
                onLocalChanged: {
                    Task { await active.refresh() }
                }
            )
        }
        .sheet(item: $previewTarget) { target in
            ExplorerQuickLookView(url: target.url)
                .ignoresSafeArea()
        }
        .sheet(isPresented: $showShareSheet) {
            ExplorerShareSheet(urls: shareURLs)
        }
        .alert(
            "Nueva carpeta",
            isPresented: $showNewFolder
        ) {
            TextField("Nombre", text: $newFolderName)

            Button("Cancelar", role: .cancel) {
                newFolderName = ""
            }

            Button("Crear") {
                createFolder()
            }
        } message: {
            Text(active.relativePath)
        }
        .alert(
            "Renombrar",
            isPresented: Binding(
                get: {
                    if case .rename = pendingAction {
                        return true
                    }
                    return false
                },
                set: {
                    if !$0, case .rename = pendingAction {
                        pendingAction = nil
                    }
                }
            )
        ) {
            TextField("Nombre", text: $renameText)

            Button("Cancelar", role: .cancel) {
                renameText = ""
                pendingAction = nil
            }

            Button("Guardar") {
                performRename()
            }
        }
        .alert(
            "Eliminar",
            isPresented: Binding(
                get: {
                    if case .delete = pendingAction {
                        return true
                    }
                    return false
                },
                set: {
                    if !$0, case .delete = pendingAction {
                        pendingAction = nil
                    }
                }
            )
        ) {
            Button("Cancelar", role: .cancel) {
                pendingAction = nil
            }

            Button("Eliminar", role: .destructive) {
                performDelete()
            }
        } message: {
            Text(
                "Los elementos seleccionados se moverán a la Papelera de Nikaido. "
                + "Podrás restaurarlos o deshacer la última eliminación."
            )
        }
        .sheet(
            isPresented: Binding(
                get: {
                    if case .extract = pendingAction {
                        return true
                    }
                    return false
                },
                set: {
                    if !$0, case .extract = pendingAction {
                        pendingAction = nil
                        archivePassword = ""
                    }
                }
            )
        ) {
            ExplorerExtractSheet(
                password: $archivePassword,
                isOperating: isOperating,
                onCancel: {
                    pendingAction = nil
                    archivePassword = ""
                },
                onExtract: {
                    performExtract()
                }
            )
        }
        .alert(
            "Nikaido Explorer",
            isPresented: Binding(
                get: { globalError != nil },
                set: {
                    if !$0 {
                        globalError = nil
                    }
                }
            )
        ) {
            Button("Entendido", role: .cancel) {
                globalError = nil
            }
        } message: {
            Text(globalError ?? "")
        }
        .onAppear {
            locations.refreshPersistentReferences()

            if leftPane.location == nil,
               let local = locations.localLocation
            {
                leftPane.openLocation(local)
            }

            if rightPane.location == nil,
               let local = locations.localLocation
            {
                rightPane.openLocation(local)
            }
        }
    }

    private var explorerTopBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "folder.fill.badge.gearshape")
                .font(.title3)
                .foregroundStyle(Color.accentColor)

            VStack(alignment: .leading, spacing: 1) {
                Text("Nikaido Explorer")
                    .font(.headline)

                Text(
                    active.location?.name
                    ?? "Sin almacenamiento"
                )
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer()

            if isOperating || operationQueue.isRunning {
                ProgressView()
                    .controlSize(.small)
            }

            Button {
                showOperations = true
            } label: {
                ZStack(alignment: .topTrailing) {
                    Image(systemName: "list.bullet.rectangle")
                    if operationQueue.activeCount > 0 {
                        Text("\(operationQueue.activeCount)")
                            .font(.system(size: 8, weight: .bold))
                            .padding(3)
                            .background(.red, in: Circle())
                            .foregroundStyle(.white)
                            .offset(x: 6, y: -6)
                    }
                }
            }
            .buttonStyle(.bordered)
            .accessibilityLabel("Cola de operaciones")

            if trash.canUndo {
                Button {
                    operationQueue.enqueue(title: "Deshacer eliminación", kind: .restore) {
                        try await trash.undoLast()
                        await leftPane.refresh()
                        await rightPane.refresh()
                    }
                } label: {
                    Image(systemName: "arrow.uturn.backward")
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Deshacer última eliminación")
            }

            Button {
                showStorageLocations = true
            } label: {
                Image(systemName: "externaldrive.fill")
            }
            .buttonStyle(.bordered)
            .accessibilityLabel("Dispositivos de almacenamiento")

            Menu {
                Section("Archivos") {
                    Button {
                        newFolderName = ""
                        showNewFolder = true
                    } label: {
                        Label(
                            "Nueva carpeta",
                            systemImage: "folder.badge.plus"
                        )
                    }
                    .disabled(active.currentURL == nil)

                    Button {
                        active.selectionMode.toggle()

                        if !active.selectionMode {
                            active.clearSelection()
                        }
                    } label: {
                        Label(
                            active.selectionMode
                            ? "Salir de selección"
                            : "Seleccionar",
                            systemImage: "checkmark.circle"
                        )
                    }

                    Button {
                        active.goRoot()
                    } label: {
                        Label(
                            "Acceso directo a la raíz",
                            systemImage: "arrow.up.to.line.compact"
                        )
                    }

                    Button {
                        guard
                            let location = active.location,
                            let currentURL = active.currentURL
                        else { return }

                        do {
                            try favorites.add(
                                location: location,
                                folderURL: currentURL
                            )
                        } catch {
                            globalError = error.localizedDescription
                        }
                    } label: {
                        Label(
                            "Añadir carpeta actual a favoritos",
                            systemImage: "star"
                        )
                    }
                    .disabled(active.currentURL == nil)

                    Button {
                        showStorageLocations = true
                    } label: {
                        Label(
                            "Favoritos",
                            systemImage: "star.fill"
                        )
                    }

                    Button {
                        Task {
                            await active.refresh()
                        }
                    } label: {
                        Label(
                            "Recargar",
                            systemImage: "arrow.clockwise"
                        )
                    }
                }

                Section("Vista") {
                    Menu("Modo de vista") {
                        ForEach(ExplorerViewMode.allCases) { mode in
                            Button {
                                active.viewMode = mode
                            } label: {
                                if active.viewMode == mode {
                                    Label(mode.title, systemImage: "checkmark")
                                } else {
                                    Label(mode.title, systemImage: mode.systemImage)
                                }
                            }
                        }
                    }

                    Menu("Ordenar por") {
                        ForEach(ExplorerSortMode.allCases) { mode in
                            Button {
                                active.sortMode = mode

                                Task {
                                    await active.refresh()
                                }
                            } label: {
                                if active.sortMode == mode {
                                    Label(
                                        mode.title,
                                        systemImage: "checkmark"
                                    )
                                } else {
                                    Text(mode.title)
                                }
                            }
                        }
                    }

                    Button {
                        active.ascending.toggle()

                        Task {
                            await active.refresh()
                        }
                    } label: {
                        Label(
                            active.ascending
                            ? "Ascendente"
                            : "Descendente",
                            systemImage: active.ascending
                            ? "arrow.up"
                            : "arrow.down"
                        )
                    }

                    Button {
                        active.showHidden.toggle()

                        Task {
                            await active.refresh()
                        }
                    } label: {
                        Label(
                            active.showHidden
                            ? "Ocultar archivos ocultos"
                            : "Mostrar archivos ocultos",
                            systemImage: active.showHidden
                            ? "eye.slash"
                            : "eye"
                        )
                    }
                }

                Section("Nikaido") {
                    Button {
                        showSMB = true
                    } label: {
                        Label("Servidor SMB", systemImage: "network")
                    }

                    Button {
                        showTrash = true
                    } label: {
                        Label("Papelera", systemImage: "trash")
                    }

                    Button {
                        showOperations = true
                    } label: {
                        Label("Cola de operaciones", systemImage: "list.bullet.rectangle")
                    }

                    Button {
                        showStorageLocations = true
                    } label: {
                        Label(
                            "Dispositivos de almacenamiento",
                            systemImage: "externaldrive.connected.to.line.below"
                        )
                    }

                    Button {
                        onOpenVault()
                    } label: {
                        Label(
                            "Nikaido Vault",
                            systemImage: "lock.square.stack.fill"
                        )
                    }

                    Button {
                        onOpenSecReader()
                    } label: {
                        Label(
                            "Abrir colección .sec",
                            systemImage: "folder.badge.gearshape"
                        )
                    }

                    Button {
                        onOpenVault()
                    } label: {
                        Label(
                            "Nikaido Link",
                            systemImage: "wifi"
                        )
                    }

                    Button {
                        showSettings = true
                    } label: {
                        Label(
                            "Ajustes",
                            systemImage: "gearshape"
                        )
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle.fill")
                    .font(.title3)
            }
            .buttonStyle(.borderedProminent)
            .accessibilityLabel("Acciones")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private func paneView(
        _ pane: ExplorerPaneState,
        index: Int
    ) -> some View {
        ExplorerPaneView(
            pane: pane,
            paneIndex: index,
            isActive: activePane == index,
            onActivate: {
                activePane = index
            },
            onOpenFile: { item in
                activePane = index
                previewTarget = ExplorerPreviewTarget(url: item.url)
            },
            onRename: { item in
                activePane = index
                renameText = item.name
                pendingAction = .rename(item, pane: index)
            },
            onDelete: { item in
                activePane = index
                requestDelete(
                    [item],
                    paneIndex: index
                )
            },
            onCopyToOther: { item in
                activePane = index
                transfer(
                    [item],
                    fromPane: index,
                    moving: false
                )
            },
            onMoveToOther: { item in
                activePane = index
                transfer(
                    [item],
                    fromPane: index,
                    moving: true
                )
            },
            onShare: { item in
                activePane = index
                shareURLs = [item.url]
                showShareSheet = true
            },
            onExtract: { item in
                activePane = index
                archivePassword = ""
                pendingAction = .extract(
                    item,
                    pane: index
                )
            },
            onCompress: { item in
                activePane = index
                compress(
                    [item],
                    paneIndex: index
                )
            },
            onDropProviders: { providers in
                handleDrop(providers, destinationPane: index)
            }
        )
    }

    private var selectionToolbar: some View {
        HStack(spacing: 8) {
            Text(
                "\(active.selectedItems.count) seleccionado(s)"
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            Spacer()

            Button {
                active.selectAll()
            } label: {
                Image(systemName: "checkmark.circle")
            }
            .buttonStyle(.bordered)
            .accessibilityLabel("Seleccionar todo")

            Button {
                transfer(
                    active.selectedItems,
                    fromPane: activePane,
                    moving: false
                )
            } label: {
                Label("Copiar", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)
            .disabled(active.selectedItems.isEmpty)

            Button {
                transfer(
                    active.selectedItems,
                    fromPane: activePane,
                    moving: true
                )
            } label: {
                Label("Mover", systemImage: "arrow.right.square")
            }
            .buttonStyle(.borderedProminent)
            .disabled(active.selectedItems.isEmpty)

            Menu {
                Button {
                    shareURLs = active.selectedItems.map(\.url)
                    showShareSheet = !shareURLs.isEmpty
                } label: {
                    Label("Compartir", systemImage: "square.and.arrow.up")
                }

                Button {
                    compress(
                        active.selectedItems,
                        paneIndex: activePane
                    )
                } label: {
                    Label("Comprimir ZIP", systemImage: "archivebox")
                }

                Button(role: .destructive) {
                    requestDelete(
                        active.selectedItems,
                        paneIndex: activePane
                    )
                } label: {
                    Label("Eliminar", systemImage: "trash")
                }
            } label: {
                Image(systemName: "ellipsis")
            }
            .buttonStyle(.bordered)
            .disabled(active.selectedItems.isEmpty)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
    }

    private func pane(at index: Int) -> ExplorerPaneState {
        index == 0 ? leftPane : rightPane
    }

    private func oppositePane(
        of index: Int
    ) -> ExplorerPaneState {
        index == 0 ? rightPane : leftPane
    }

    private func createFolder() {
        guard
            let currentURL = active.currentURL,
            let location = active.location
        else {
            return
        }

        let name = newFolderName
        newFolderName = ""

        Task {
            isOperating = true
            defer { isOperating = false }

            do {
                try await ExplorerFileEngine.createFolder(
                    named: name,
                    in: currentURL,
                    root: location.rootURL
                )
                await active.refresh()
            } catch {
                globalError = error.localizedDescription
            }
        }
    }

    private func performRename() {
        guard case .rename(let item, let paneIndex) = pendingAction else {
            return
        }

        let targetPane = pane(at: paneIndex)

        guard let location = targetPane.location else {
            return
        }

        let name = renameText
        renameText = ""
        pendingAction = nil

        Task {
            isOperating = true
            defer { isOperating = false }

            do {
                try await ExplorerFileEngine.rename(
                    item,
                    to: name,
                    root: location.rootURL
                )
                await targetPane.refresh()
            } catch {
                globalError = error.localizedDescription
            }
        }
    }

    private func requestDelete(
        _ items: [ExplorerFileItem],
        paneIndex: Int
    ) {
        guard !items.isEmpty else { return }

        if confirmDelete {
            pendingAction = .delete(
                items,
                pane: paneIndex
            )
        } else {
            pendingAction = .delete(
                items,
                pane: paneIndex
            )
            performDelete()
        }
    }

    private func performDelete() {
        guard case .delete(let items, let paneIndex) = pendingAction else {
            return
        }
        let targetPane = pane(at: paneIndex)
        guard let location = targetPane.location else { return }
        pendingAction = nil

        operationQueue.enqueue(
            title: items.count == 1 ? "Eliminar \(items[0].name)" : "Eliminar \(items.count) elementos",
            kind: .trash,
            totalUnits: items.count
        ) {
            try await trash.moveToTrash(items, root: location.rootURL)
            await targetPane.refresh()
        }
    }

    private func transfer(
        _ items: [ExplorerFileItem],
        fromPane paneIndex: Int,
        moving: Bool
    ) {
        guard !items.isEmpty else { return }

        let sourcePane = pane(at: paneIndex)
        let destinationPane = oppositePane(of: paneIndex)
        guard let sourceRoot = sourcePane.location?.rootURL,
              let destinationRoot = destinationPane.location?.rootURL,
              let destinationDirectory = destinationPane.currentURL
        else {
            globalError = "Abre una ubicación en ambos paneles primero."
            return
        }

        let title = moving
            ? (items.count == 1 ? "Mover \(items[0].name)" : "Mover \(items.count) elementos")
            : (items.count == 1 ? "Copiar \(items[0].name)" : "Copiar \(items.count) elementos")

        operationQueue.enqueue(
            title: title,
            kind: moving ? .move : .copy,
            totalUnits: items.count
        ) {
            if moving {
                try await ExplorerFileEngine.move(
                    items, sourceRoot: sourceRoot, to: destinationDirectory,
                    destinationRoot: destinationRoot, conflictPolicy: conflictPolicy
                )
            } else {
                try await ExplorerFileEngine.copy(
                    items, sourceRoot: sourceRoot, to: destinationDirectory,
                    destinationRoot: destinationRoot, conflictPolicy: conflictPolicy
                )
            }
            await sourcePane.refresh()
            await destinationPane.refresh()
        }
        sourcePane.clearSelection()
        sourcePane.selectionMode = false
    }

    private func handleDrop(_ providers: [NSItemProvider], destinationPane: Int) -> Bool {
        Task {
            do {
                let payload = try await ExplorerDragPayload.load(from: providers)
                guard payload.sourcePane != destinationPane else { return }
                let sourcePane = pane(at: payload.sourcePane)
                let urlSet = Set(payload.urls)
                let dragged = sourcePane.items.filter { urlSet.contains($0.url.absoluteString) }
                guard !dragged.isEmpty else {
                    globalError = "Los archivos arrastrados ya no están en el panel de origen."
                    return
                }
                transfer(dragged, fromPane: payload.sourcePane, moving: true)
            } catch {
                globalError = error.localizedDescription
            }
        }
        return true
    }

    private func compress(
        _ items: [ExplorerFileItem],
        paneIndex: Int
    ) {
        guard !items.isEmpty else { return }

        let targetPane = pane(at: paneIndex)

        guard
            let currentURL = targetPane.currentURL,
            let root = targetPane.location?.rootURL
        else {
            return
        }

        Task {
            isOperating = true
            defer { isOperating = false }

            do {
                _ = try await ExplorerArchiveManager.createZIP(
                    from: items,
                    in: currentURL,
                    root: root
                )
                await targetPane.refresh()
            } catch {
                globalError = error.localizedDescription
            }
        }
    }

    private func performExtract() {
        guard case .extract(let item, let paneIndex) = pendingAction else {
            return
        }

        let targetPane = pane(at: paneIndex)

        guard
            let currentURL = targetPane.currentURL,
            let root = targetPane.location?.rootURL
        else {
            return
        }

        let password = archivePassword.isEmpty
            ? nil
            : archivePassword

        pendingAction = nil
        archivePassword = ""

        Task {
            isOperating = true
            defer { isOperating = false }

            var destination = currentURL.appendingPathComponent(
                item.url.deletingPathExtension().lastPathComponent,
                isDirectory: true
            )

            if FileManager.default.fileExists(
                atPath: destination.path
            ) {
                destination = ExplorerFileEngine.uniqueDestination(
                    for: destination,
                    in: currentURL
                )
            }

            do {
                try await ExplorerArchiveManager.extract(
                    archiveURL: item.url,
                    to: destination,
                    root: root,
                    password: password
                )

                await targetPane.refresh()
            } catch {
                globalError = error.localizedDescription
            }
        }
    }
}

struct ExplorerPaneView: View {
    @ObservedObject var pane: ExplorerPaneState

    let paneIndex: Int
    let isActive: Bool
    let onActivate: () -> Void
    let onOpenFile: (ExplorerFileItem) -> Void
    let onRename: (ExplorerFileItem) -> Void
    let onDelete: (ExplorerFileItem) -> Void
    let onCopyToOther: (ExplorerFileItem) -> Void
    let onMoveToOther: (ExplorerFileItem) -> Void
    let onShare: (ExplorerFileItem) -> Void
    let onExtract: (ExplorerFileItem) -> Void
    let onCompress: (ExplorerFileItem) -> Void
    let onDropProviders: ([NSItemProvider]) -> Bool

    var body: some View {
        VStack(spacing: 0) {
            paneHeader

            Divider()

            if pane.isLoading && pane.items.isEmpty {
                Spacer()
                ProgressView("Leyendo…")
                Spacer()
            } else if pane.currentURL == nil {
                emptyLocation
            } else {
                fileContent
            }
        }
        .background(
            isActive
            ? Color.accentColor.opacity(0.035)
            : Color.clear
        )
        .contentShape(Rectangle())
        .onTapGesture {
            onActivate()
        }
    }

    private var paneHeader: some View {
        VStack(spacing: 6) {
            HStack(spacing: 6) {
                Button {
                    onActivate()
                    pane.goUp()
                } label: {
                    Image(systemName: "chevron.up")
                }
                .buttonStyle(.bordered)
                .disabled(!pane.canGoUp)

                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 5) {
                        Text(pane.title)
                            .font(.subheadline.bold())
                            .lineLimit(1)

                        if isActive {
                            Circle()
                                .fill(Color.accentColor)
                                .frame(width: 6, height: 6)
                        }
                    }

                    Text(pane.relativePath)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Spacer()

                Button {
                    pane.viewMode = pane.viewMode == .list
                        ? .grid
                        : .list
                } label: {
                    Image(systemName: pane.viewMode == .list
                        ? "square.grid.2x2"
                        : "list.bullet")
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Cambiar vista")

                if pane.selectionMode {
                    Button {
                        pane.selectAll()
                    } label: {
                        Image(systemName: "checkmark.circle")
                    }
                    .buttonStyle(.bordered)
                }

                Button {
                    Task {
                        await pane.refresh()
                    }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
            }

            TextField(
                "Buscar en este panel",
                text: $pane.search
            )
            .textFieldStyle(.roundedBorder)
            .onSubmit {
                Task {
                    await pane.refresh()
                }
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 7)
    }

    @ViewBuilder
    private var fileContent: some View {
        if pane.viewMode == .grid {
            fileGrid
        } else {
            fileList
        }
    }

    private var fileList: some View {
        List {
            if let error = pane.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if pane.items.isEmpty && pane.errorMessage == nil {
                emptyFolderRow
            }

            ForEach(pane.items) { item in
                ExplorerFileRow(
                    item: item,
                    selected: pane.selectedIDs.contains(item.id),
                    selectionMode: pane.selectionMode
                )
                .contentShape(Rectangle())
                .onTapGesture {
                    activate(item)
                }
                .contextMenu {
                    itemContextMenu(item)
                }
                .onDrag { dragProvider(for: item) }
            }
        }
        .onDrop(of: [UTType.nikaidoExplorerItems.identifier], isTargeted: nil) { providers in
            onDropProviders(providers)
        }
        .listStyle(.plain)
        .refreshable {
            await pane.refresh()
        }
    }

    private var fileGrid: some View {
        ScrollView {
            if let error = pane.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
            }

            if pane.items.isEmpty && pane.errorMessage == nil {
                VStack(spacing: 10) {
                    Image(systemName: "folder")
                        .font(.system(size: 34))
                        .foregroundStyle(.secondary)
                    Text("Carpeta vacía")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity, minHeight: 170)
            } else {
                LazyVGrid(
                    columns: [
                        GridItem(
                            .adaptive(minimum: 100, maximum: 145),
                            spacing: 10
                        )
                    ],
                    spacing: 10
                ) {
                    ForEach(pane.items) { item in
                        ExplorerFileGridCell(
                            item: item,
                            selected: pane.selectedIDs.contains(item.id),
                            selectionMode: pane.selectionMode
                        )
                        .contentShape(Rectangle())
                        .onTapGesture {
                            activate(item)
                        }
                        .contextMenu {
                            itemContextMenu(item)
                        }
                        .onDrag { dragProvider(for: item) }
                    }
                }
                .padding(10)
            }
        }
        .onDrop(of: [UTType.nikaidoExplorerItems.identifier], isTargeted: nil) { providers in
            onDropProviders(providers)
        }
        .refreshable {
            await pane.refresh()
        }
    }

    private func dragProvider(for item: ExplorerFileItem) -> NSItemProvider {
        let items: [ExplorerFileItem]
        if pane.selectedIDs.contains(item.id), !pane.selectedItems.isEmpty {
            items = pane.selectedItems
        } else {
            items = [item]
        }
        return ExplorerDragPayload(
            urls: items.map { $0.url.absoluteString },
            sourcePane: paneIndex
        ).itemProvider()
    }

    private var emptyFolderRow: some View {
        VStack(spacing: 10) {
            Image(systemName: "folder")
                .font(.system(size: 34))
                .foregroundStyle(.secondary)

            Text("Carpeta vacía")
                .font(.headline)
        }
        .frame(
            maxWidth: .infinity,
            minHeight: 150
        )
        .listRowSeparator(.hidden)
    }

    private func activate(_ item: ExplorerFileItem) {
        onActivate()

        if pane.selectionMode {
            pane.toggleSelection(item)
        } else if item.isDirectory {
            pane.open(item)
        } else {
            onOpenFile(item)
        }
    }

    @ViewBuilder
    private func itemContextMenu(_ item: ExplorerFileItem) -> some View {
        if item.isDirectory {
            Button {
                pane.open(item)
            } label: {
                Label("Abrir", systemImage: "folder")
            }
        } else {
            Button {
                onOpenFile(item)
            } label: {
                Label("Vista rápida", systemImage: "eye")
            }
        }

        Button {
            onCopyToOther(item)
        } label: {
            Label(
                "Copiar al otro panel",
                systemImage: "doc.on.doc"
            )
        }

        Button {
            onMoveToOther(item)
        } label: {
            Label(
                "Mover al otro panel",
                systemImage: "arrow.right.square"
            )
        }

        Button {
            onRename(item)
        } label: {
            Label("Renombrar", systemImage: "pencil")
        }

        Button {
            onShare(item)
        } label: {
            Label(
                "Compartir",
                systemImage: "square.and.arrow.up"
            )
        }

        Button {
            onCompress(item)
        } label: {
            Label(
                "Comprimir en ZIP",
                systemImage: "archivebox"
            )
        }

        if item.isArchive {
            Button {
                onExtract(item)
            } label: {
                Label(
                    "Extraer…",
                    systemImage: "archivebox.fill"
                )
            }
        }

        Button(role: .destructive) {
            onDelete(item)
        } label: {
            Label("Eliminar", systemImage: "trash")
        }
    }

    private var emptyLocation: some View {
        VStack(spacing: 12) {
            Spacer()

            Image(systemName: "externaldrive.badge.questionmark")
                .font(.system(size: 42))
                .foregroundStyle(.secondary)

            Text("Sin ubicación")
                .font(.headline)

            Text(
                "Elige un dispositivo de almacenamiento "
                + "desde el botón de la parte superior."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal)

            Spacer()
        }
    }
}

private struct ExplorerFileRow: View {
    let item: ExplorerFileItem
    let selected: Bool
    let selectionMode: Bool

    var body: some View {
        HStack(spacing: 10) {
            if selectionMode {
                Image(
                    systemName: selected
                    ? "checkmark.circle.fill"
                    : "circle"
                )
                .foregroundStyle(
                    selected ? Color.accentColor : .secondary
                )
            }

            Image(systemName: item.systemImage)
                .font(.title3)
                .foregroundStyle(
                    item.isDirectory
                    ? Color.accentColor
                    : Color.secondary
                )
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 3) {
                Text(item.name)
                    .lineLimit(2)

                HStack(spacing: 7) {
                    if !item.formattedSize.isEmpty {
                        Text(item.formattedSize)
                    }

                    if let modified = item.modifiedAt {
                        Text(
                            modified.formatted(
                                date: .numeric,
                                time: .shortened
                            )
                        )
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }

            Spacer()

            if item.isDirectory {
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 2)
    }
}


private struct ExplorerFileGridCell: View {
    let item: ExplorerFileItem
    let selected: Bool
    let selectionMode: Bool

    var body: some View {
        VStack(spacing: 7) {
            ZStack(alignment: .topTrailing) {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(uiColor: .secondarySystemBackground))
                    .aspectRatio(1.15, contentMode: .fit)

                Image(systemName: item.systemImage)
                    .font(.system(size: 38))
                    .foregroundStyle(
                        item.isDirectory
                        ? Color.accentColor
                        : Color.secondary
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                if selectionMode {
                    Image(
                        systemName: selected
                        ? "checkmark.circle.fill"
                        : "circle"
                    )
                    .foregroundStyle(
                        selected ? Color.accentColor : Color.secondary
                    )
                    .background(Circle().fill(.background))
                    .padding(6)
                }
            }

            Text(item.name)
                .font(.caption)
                .multilineTextAlignment(.center)
                .lineLimit(2)
                .frame(maxWidth: .infinity)

            if !item.formattedSize.isEmpty {
                Text(item.formattedSize)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(5)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .stroke(
                    selected ? Color.accentColor : Color.clear,
                    lineWidth: 2
                )
        )
    }
}

struct ExplorerStorageLocationsView: View {
    @ObservedObject var locations: SecurityScopedFolderStore
    @ObservedObject var favorites: ExplorerFavoritesStore
    @ObservedObject var leftPane: ExplorerPaneState
    @ObservedObject var rightPane: ExplorerPaneState

    @Binding var activePane: Int

    let onAddLocation: () -> Void

    @Environment(\.dismiss) private var dismiss

    private var active: ExplorerPaneState {
        activePane == 0 ? leftPane : rightPane
    }

    var body: some View {
        NavigationView {
            List {
                if !favorites.favorites.isEmpty {
                    Section("Favoritos") {
                        ForEach(favorites.favorites) { favorite in
                            Button {
                                guard let resolved = favorites.resolve(
                                    favorite,
                                    locations: locations.locations
                                ) else {
                                    return
                                }

                                active.openLocation(
                                    resolved.0,
                                    folderURL: resolved.1
                                )
                                dismiss()
                            } label: {
                                HStack {
                                    Image(systemName: "star.fill")
                                        .foregroundStyle(.yellow)

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(favorite.name)

                                        if let resolved = favorites.resolve(
                                            favorite,
                                            locations: locations.locations
                                        ) {
                                            Text(resolved.0.name)
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                        } else {
                                            Text("Ubicación no disponible")
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                        }
                                    }
                                }
                            }
                            .disabled(
                                favorites.resolve(
                                    favorite,
                                    locations: locations.locations
                                ) == nil
                            )
                            .swipeActions {
                                Button(role: .destructive) {
                                    favorites.remove(favorite)
                                } label: {
                                    Label("Quitar", systemImage: "star.slash")
                                }
                            }
                        }
                    }
                }

                Section("Dispositivos de almacenamiento") {
                    ForEach(locations.locations) { location in
                        Button {
                            active.openLocation(location)
                            dismiss()
                        } label: {
                            HStack {
                                Image(
                                    systemName: location.kind == .local
                                    ? "iphone"
                                    : "externaldrive"
                                )

                                VStack(alignment: .leading) {
                                    Text(location.name)

                                    Text(
                                        location.kind == .local
                                        ? "Almacenamiento de Nikaido Explorer"
                                        : location.isPersistentReference
                                            ? "Carpeta autorizada por iOS"
                                            : "Autorizada solo para esta sesión"
                                    )
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                }

                                Spacer()

                                if active.location?.id == location.id {
                                    Image(systemName: "checkmark")
                                }
                            }
                        }
                        .swipeActions {
                            if location.kind == .authorized {
                                Button(role: .destructive) {
                                    removeLocation(location)
                                } label: {
                                    Label("Quitar", systemImage: "trash")
                                }
                            }
                        }
                    }
                }

                Section {
                    Button {
                        onAddLocation()
                    } label: {
                        Label(
                            "Añadir carpeta o almacenamiento…",
                            systemImage: "plus.circle.fill"
                        )
                    }
                }

                Section {
                    Text(
                        "Selecciona una carpeta desde Archivos para autorizarla. "
                        + "Nikaido Explorer puede trabajar dentro de esa raíz y "
                        + "sus subcarpetas mientras iOS mantenga el permiso. No "
                        + "equivale a acceso root del sistema."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Almacenamiento")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cerrar") {
                        dismiss()
                    }
                }
            }
        }
    }

    private func removeLocation(_ location: ExplorerStorageLocation) {
        favorites.removeFavorites(for: location.id)

        if leftPane.location?.id == location.id,
           let local = locations.localLocation
        {
            leftPane.openLocation(local)
        }

        if rightPane.location?.id == location.id,
           let local = locations.localLocation
        {
            rightPane.openLocation(local)
        }

        locations.remove(location)
    }
}

struct ExplorerSettingsView: View {
    @Binding var conflictPolicyRaw: String
    @Binding var confirmDelete: Bool

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            Form {
                Section("Copiar y mover") {
                    Picker(
                        "Si ya existe",
                        selection: $conflictPolicyRaw
                    ) {
                        ForEach(ExplorerConflictPolicy.allCases) { policy in
                            Text(policy.title)
                                .tag(policy.rawValue)
                        }
                    }
                }

                Section("Seguridad") {
                    Toggle(
                        "Confirmar antes de eliminar",
                        isOn: $confirmDelete
                    )
                }

                Section("Paneles") {
                    Text(
                        "En vertical puedes cambiar entre Panel 1 y Panel 2. "
                        + "En horizontal, Nikaido Explorer muestra ambos paneles "
                        + "simultáneamente para copiar y mover entre ellos."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Raíz") {
                    Text(
                        "“Acceso directo a la raíz” significa la raíz de la "
                        + "ubicación que autorizaste. iOS no permite que una app "
                        + "normal navegue la raíz / del sistema ni los contenedores "
                        + "privados de otras apps."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Archivos comprimidos") {
                    LabeledContent("ZIP", value: "Extraer + crear")
                    LabeledContent("7z", value: "Extraer")
                    LabeledContent("RAR", value: "Extraer")
                }
            }
            .navigationTitle("Ajustes")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cerrar") {
                        dismiss()
                    }
                }
            }
        }
    }
}

struct ExplorerExtractSheet: View {
    @Binding var password: String

    let isOperating: Bool
    let onCancel: () -> Void
    let onExtract: () -> Void

    var body: some View {
        NavigationView {
            Form {
                Section("Extraer archivo") {
                    Text(
                        "Se creará una carpeta con el nombre del archivo "
                        + "comprimido y se extraerá dentro."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Contraseña opcional") {
                    SecureField(
                        "Contraseña (RAR cifrado)",
                        text: $password
                    )
                    .textContentType(.password)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                    Text(
                        "ZIP y 7z cifrados dependen de las capacidades de las "
                        + "librerías actuales. RAR admite contraseña."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                if isOperating {
                    Section {
                        ProgressView("Extrayendo…")
                    }
                }
            }
            .navigationTitle("Extraer")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancelar") {
                        onCancel()
                    }
                    .disabled(isOperating)
                }

                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Extraer") {
                        onExtract()
                    }
                    .disabled(isOperating)
                }
            }
        }
    }
}

private struct ExplorerPreviewTarget: Identifiable {
    let id = UUID()
    let url: URL
}
