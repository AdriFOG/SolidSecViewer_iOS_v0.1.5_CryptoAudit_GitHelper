import UIKit

@MainActor
enum PrivacyShield {
    private static let overlayTag = 0x534F4C49
    private static let messageTag = 0x534F4C4D

    static func isScreenCaptureActive() -> Bool {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .contains { $0.screen.isCaptured }
    }

    static func show(message: String? = nil) {
        for window in appWindows() {
            let overlay: UIView

            if let existing = window.viewWithTag(overlayTag) {
                overlay = existing
            } else {
                let view = UIView(frame: .zero)
                view.tag = overlayTag
                view.translatesAutoresizingMaskIntoConstraints = false
                view.backgroundColor = .black
                view.isUserInteractionEnabled = true

                let stack = UIStackView()
                stack.axis = .vertical
                stack.alignment = .center
                stack.spacing = 14
                stack.translatesAutoresizingMaskIntoConstraints = false

                let icon = UIImageView(
                    image: UIImage(
                        systemName: "lock.shield.fill",
                        withConfiguration: UIImage.SymbolConfiguration(
                            pointSize: 48,
                            weight: .semibold
                        )
                    )
                )
                icon.tintColor = .white
                icon.contentMode = .scaleAspectFit

                let label = UILabel()
                label.tag = messageTag
                label.textColor = .white
                label.font = .preferredFont(forTextStyle: .headline)
                label.textAlignment = .center
                label.numberOfLines = 0
                label.translatesAutoresizingMaskIntoConstraints = false

                stack.addArrangedSubview(icon)
                stack.addArrangedSubview(label)
                view.addSubview(stack)
                window.addSubview(view)

                NSLayoutConstraint.activate([
                    view.leadingAnchor.constraint(equalTo: window.leadingAnchor),
                    view.trailingAnchor.constraint(equalTo: window.trailingAnchor),
                    view.topAnchor.constraint(equalTo: window.topAnchor),
                    view.bottomAnchor.constraint(equalTo: window.bottomAnchor),

                    stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                    stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
                    stack.leadingAnchor.constraint(
                        greaterThanOrEqualTo: view.leadingAnchor,
                        constant: 28
                    ),
                    stack.trailingAnchor.constraint(
                        lessThanOrEqualTo: view.trailingAnchor,
                        constant: -28
                    )
                ])

                overlay = view
            }

            if let label = overlay.viewWithTag(messageTag) as? UILabel {
                label.text = message ?? ""
                label.isHidden = message == nil
            }

            window.bringSubviewToFront(overlay)
        }
    }

    static func hide() {
        for window in appWindows() {
            window.viewWithTag(overlayTag)?.removeFromSuperview()
        }
    }

    private static func appWindows() -> [UIWindow] {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .filter { !$0.isHidden }
    }
}
