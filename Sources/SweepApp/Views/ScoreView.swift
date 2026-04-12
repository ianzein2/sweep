import SwiftUI
import SweepCore

struct ScoreView: View {
    let score: SecurityScore?

    var body: some View {
        HStack(spacing: 12) {
            // Score circle
            ZStack {
                Circle()
                    .stroke(scoreColor.opacity(0.2), lineWidth: 6)
                    .frame(width: 64, height: 64)

                Circle()
                    .trim(from: 0, to: Double(score?.total ?? 0) / 100.0)
                    .stroke(scoreColor, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                    .frame(width: 64, height: 64)
                    .rotationEffect(.degrees(-90))

                VStack(spacing: 0) {
                    if let score = score {
                        Text("\(score.total)")
                            .font(.system(size: 20, weight: .bold, design: .rounded))
                        Text("/100")
                            .font(.system(size: 10))
                            .foregroundColor(.secondary)
                    } else {
                        Text("—")
                            .font(.system(size: 20, weight: .bold, design: .rounded))
                            .foregroundColor(.secondary)
                    }
                }
            }

            // Grade
            if let score = score {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Grade: \(score.grade)")
                        .font(.headline)
                    Text("\(score.deductions.count) deduction\(score.deductions.count == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    Text("No scan yet")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    Text("13 scanners ready")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private var scoreColor: Color {
        guard let total = score?.total else { return .gray }
        switch total {
        case 90...100: return .green
        case 70..<90:  return .yellow
        case 50..<70:  return .orange
        default:       return .red
        }
    }
}
