import SwiftUI
import SweepCore

struct ScannerResultView: View {
    let result: ScanResult

    @State private var isExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            if result.findings.isEmpty && result.errors.isEmpty {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text("No issues found")
                        .foregroundColor(.secondary)
                }
                .padding(.vertical, 2)
            }

            ForEach(result.findings.sorted(by: { $0.severity > $1.severity }),
                    id: \.title) { finding in
                FindingRow(finding: finding)
            }

            ForEach(result.errors, id: \.self) { error in
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                        .font(.caption)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        } label: {
            HStack {
                Text(result.scannerName)
                    .font(.headline)

                Spacer()

                if !result.findings.isEmpty {
                    let high = result.findings.filter { $0.severity == .high }.count
                    let medium = result.findings.filter { $0.severity == .medium }.count
                    let low = result.findings.filter { $0.severity == .low }.count

                    HStack(spacing: 6) {
                        if high > 0 {
                            badge("\(high)", color: .red)
                        }
                        if medium > 0 {
                            badge("\(medium)", color: .orange)
                        }
                        if low > 0 {
                            badge("\(low)", color: .blue)
                        }
                    }
                } else {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                }

                Text(String(format: "%.1fs", result.duration))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(width: 40, alignment: .trailing)
            }
        }
    }

    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .foregroundColor(color)
            .cornerRadius(4)
    }
}
