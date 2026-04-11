import SwiftUI
import SweepCore

struct FindingRow: View {
    let finding: Finding
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                severityDot
                    .frame(width: 10, height: 10)

                Text("[\(finding.severity.rawValue)]")
                    .font(.caption.bold())
                    .foregroundColor(severityColor)

                Text(finding.title)
                    .font(.body)

                Spacer()

                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .foregroundColor(.secondary)
                    .font(.caption)
            }
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isExpanded.toggle()
                }
            }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(finding.detail)
                        .font(.callout)
                        .foregroundColor(.secondary)

                    if let path = finding.path {
                        HStack(spacing: 4) {
                            Image(systemName: "folder")
                                .font(.caption2)
                            Text(path)
                                .font(.caption)
                                .textSelection(.enabled)
                        }
                        .foregroundColor(.secondary)
                    }

                    if let remediation = finding.remediation {
                        HStack(alignment: .top, spacing: 4) {
                            Image(systemName: "wrench")
                                .font(.caption2)
                            Text(remediation)
                                .font(.caption)
                        }
                        .foregroundColor(.blue)
                        .padding(6)
                        .background(Color.blue.opacity(0.05))
                        .cornerRadius(4)
                    }
                }
                .padding(.leading, 18)
                .padding(.vertical, 4)
            }
        }
        .padding(.vertical, 2)
    }

    private var severityDot: some View {
        Circle()
            .fill(severityColor)
    }

    private var severityColor: Color {
        switch finding.severity {
        case .high:   return .red
        case .medium: return .orange
        case .low:    return .blue
        }
    }
}
