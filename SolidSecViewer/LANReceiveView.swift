import SwiftUI
import UIKit

struct LANReceiveView: View {
    @ObservedObject var vault: PrivateVaultSession

    let parentID: UUID?

    @Environment(\.dismiss) private var dismiss
    @StateObject private var receiver = LANVaultReceiver()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    Image(systemName: "wifi.circle.fill")
                        .font(.system(size: 62))
                        .foregroundStyle(.secondary)

                    Text("Recibir .sec desde PC")
                        .font(.title2.bold())

                    Text(
                        "La PC abre el ZIP localmente y envía únicamente los "
                        + "archivos cifrados de la carpeta .sec. El ZIP de 12 GB "
                        + "nunca se guarda en el iPhone."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                    if receiver.state == .completed {
                        completedView
                    } else if receiver.state == .failed {
                        failureView
                    } else {
                        connectionInfo
                    }
                }
                .padding()
            }
            .navigationTitle("Transferencia LAN")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cerrar") {
                        receiver.stop()
                        dismiss()
                    }
                }
            }
        }
        .onAppear {
            receiver.start(
                vault: vault,
                parentID: parentID
            )
        }
        .onDisappear {
            if receiver.state != .completed {
                receiver.stop()
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            receiver.stop()
            dismiss()
        }
    }

    @ViewBuilder
    private var connectionInfo: some View {
        if let port = receiver.port {
            VStack(spacing: 12) {
                infoRow(
                    title: "IP del iPhone",
                    value: receiver.address
                )

                infoRow(
                    title: "Puerto",
                    value: String(port)
                )

                infoRow(
                    title: "Código de transferencia",
                    value: receiver.token
                )

                Button {
                    UIPasteboard.general.string =
                        "\(receiver.address)|\(port)|\(receiver.token)"
                } label: {
                    Label(
                        "Copiar IP, puerto y código",
                        systemImage: "doc.on.doc"
                    )
                }
                .buttonStyle(.bordered)

                Text(
                    "En la PC ejecuta ENVIAR_SEC_A_IPHONE.bat y selecciona "
                    + "tu ZIP o directamente la carpeta .sec."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

                Divider()

                if receiver.state == .receiving {
                    VStack(spacing: 8) {
                        if !receiver.collectionName.isEmpty {
                            Text(receiver.collectionName)
                                .font(.headline)
                                .lineLimit(2)
                        }

                        if !receiver.currentFilename.isEmpty {
                            Text(receiver.currentFilename)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }

                        ProgressView(value: receiver.progress)

                        Text(progressText)
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)

                        Text(
                            "\(receiver.filesReceived) / "
                            + "\(receiver.expectedFiles) archivos completos"
                        )
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    }
                } else {
                    ProgressView("Esperando a la PC…")
                }

                Text(
                    "Mantén SolidSec abierto y ambos equipos en la misma red "
                    + "Wi‑Fi hasta terminar."
                )
                .font(.caption)
                .foregroundStyle(.orange)
                .multilineTextAlignment(.center)
            }
        } else {
            ProgressView("Abriendo receptor Wi‑Fi…")
        }
    }

    private var completedView: some View {
        VStack(spacing: 14) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(.green)

            Text("Colección .sec guardada")
                .font(.headline)

            if let name = receiver.completedEntryName {
                Text(name)
                    .font(.footnote)
                    .multilineTextAlignment(.center)
            }

            Text(
                "Solo los archivos cifrados de Solid Explorer quedaron "
                + "almacenados, cada uno además protegido por AES‑256‑GCM "
                + "de Mi bóveda."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)

            Button("Volver a Mi bóveda") {
                dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private var failureView: some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 46))
                .foregroundStyle(.orange)

            Text(receiver.errorMessage ?? "La transferencia falló.")
                .font(.footnote)
                .multilineTextAlignment(.center)

            Button("Intentar otra vez") {
                receiver.start(
                    vault: vault,
                    parentID: parentID
                )
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private func infoRow(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)

            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        .background(.quaternary)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private var progressText: String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file

        let received = formatter.string(
            fromByteCount: receiver.bytesReceived
        )

        let expected = formatter.string(
            fromByteCount: receiver.expectedBytes
        )

        return "\(received) / \(expected) • \(Int(receiver.progress * 100))%"
    }
}
