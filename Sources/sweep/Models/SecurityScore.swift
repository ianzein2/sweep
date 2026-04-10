import Foundation

struct SecurityScore {
    let total: Int      // 0-100
    let grade: String   // A, B, C, D, F
    let deductions: [Deduction]

    struct Deduction {
        let points: Int
        let title: String
        let severity: Severity
    }

    static func calculate(from results: [ScanResult]) -> SecurityScore {
        let allFindings = results.flatMap { $0.findings }
        var deductions: [Deduction] = []

        for finding in allFindings {
            let points: Int
            switch finding.severity {
            case .high:   points = 15
            case .medium: points = 5
            case .low:    points = 1
            }
            deductions.append(Deduction(points: points, title: finding.title, severity: finding.severity))
        }

        let totalDeduction = deductions.reduce(0) { $0 + $1.points }
        let score = max(0, 100 - totalDeduction)

        let grade: String
        switch score {
        case 90...100: grade = "A"
        case 80..<90:  grade = "B"
        case 70..<80:  grade = "C"
        case 60..<70:  grade = "D"
        default:       grade = "F"
        }

        // Sort deductions by points descending
        let sorted = deductions.sorted { $0.points > $1.points }

        return SecurityScore(total: score, grade: grade, deductions: sorted)
    }
}
