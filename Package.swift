// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "sweep",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    ],
    targets: [
        .executableTarget(
            name: "sweep",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            linkerSettings: [
                .linkedFramework("CoreGraphics"),
                .linkedFramework("Security"),
            ]
        ),
    ]
)
