import SwiftUI
import SweepCore

struct ContentView: View {
    @StateObject private var engine = ScanEngine()

    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerView
                .padding()
                .background(Color(.windowBackgroundColor))

            Divider()

            // Progress bar during scanning
            if engine.isScanning {
                VStack(spacing: 4) {
                    ProgressView(value: engine.progress, total: 1.0)
                    Text(engine.currentScanner)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }

            // Results or empty state
            if engine.results.isEmpty && !engine.isScanning {
                emptyState
            } else if !engine.results.isEmpty {
                resultsList
            }

            Divider()

            // Footer
            if !engine.results.isEmpty {
                footerView
                    .padding(.horizontal)
                    .padding(.vertical, 8)
            }
        }
        .frame(minWidth: 600, minHeight: 400)
    }

    // MARK: - Header

    private var headerView: some View {
        HStack {
            if let score = engine.score {
                ScoreView(score: score)
            } else {
                ScoreView(score: nil)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 8) {
                HStack(spacing: 8) {
                    Button("Scan") {
                        engine.startScan()
                    }
                    .disabled(engine.isScanning)

                    Button("Scan as Admin") {
                        engine.scanAsAdmin()
                    }
                    .disabled(engine.isScanning)
                }

                if let date = engine.scanDate {
                    Text("Last scan: \(date.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                if engine.isRoot {
                    Text("Running as root")
                        .font(.caption)
                        .foregroundColor(.green)
                } else {
                    Text("Running as user — use Scan as Admin for full results")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Click Scan to check your Mac for spyware")
                .font(.title3)
                .foregroundColor(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Results list

    private var resultsList: some View {
        List {
            ForEach(engine.results, id: \.scannerName) { result in
                ScannerResultView(result: result)
            }
        }
        .listStyle(.inset(alternatesRowBackgrounds: true))
    }

    // MARK: - Footer

    private var footerView: some View {
        let allFindings = engine.results.flatMap { $0.findings }
        let high = allFindings.filter { $0.severity == .high }.count
        let medium = allFindings.filter { $0.severity == .medium }.count
        let low = allFindings.filter { $0.severity == .low }.count

        return HStack {
            HStack(spacing: 12) {
                Label("\(high) HIGH", systemImage: "exclamationmark.circle.fill")
                    .foregroundColor(high > 0 ? .red : .secondary)
                Label("\(medium) MEDIUM", systemImage: "exclamationmark.triangle.fill")
                    .foregroundColor(medium > 0 ? .orange : .secondary)
                Label("\(low) LOW", systemImage: "info.circle.fill")
                    .foregroundColor(low > 0 ? .blue : .secondary)
            }
            .font(.caption)

            Spacer()

            Text("\(engine.results.count) scanners completed")
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}
