# 🛡️ NetSecure

**NetSecure** is an Android network analyzer app that monitors and captures real-time network traffic on your device using a local VPN service. It gives you full visibility into which apps are making network connections, where they're connecting to, and how much data they're using — all without requiring root access.

---

## ✨ Features

- **Real-Time Traffic Capture** — Intercepts and inspects TCP/UDP packets through a local VPN tunnel
- **Per-App Traffic Breakdown** — See exactly which apps are sending and receiving data
- **Connection Logging** — Detailed logs of every connection with destination IP, port, and protocol
- **Dashboard Overview** — Clean, at-a-glance view of network activity across all apps
- **App Detail View** — Drill into individual app traffic with connection-level detail
- **Security Reports** — Generate reports of suspicious or unusual network behavior
- **No Root Required** — Uses Android's VPN Service API for packet capture

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Language** | Kotlin |
| **UI** | Jetpack Compose + Material 3 |
| **Architecture** | MVVM (ViewModel + Repository) |
| **Navigation** | Jetpack Navigation Compose |
| **Network Capture** | Android VPN Service API |
| **Min SDK** | Android 7.0 (API 24) |

---

## 📁 Project Structure

```
app/src/main/java/com/example/netsecure/
├── MainActivity.kt                  # Entry point
├── data/
│   ├── model/
│   │   ├── AppTrafficInfo.kt        # Per-app traffic data model
│   │   └── ConnectionRecord.kt      # Individual connection data model
│   └── TrafficRepository.kt         # Data layer for traffic records
├── navigation/
│   └── NavGraph.kt                  # Navigation routes & graph
├── service/
│   ├── LocalVpnService.kt           # VPN service for packet capture
│   ├── PacketParser.kt              # Raw packet parsing
│   └── vpn/
│       ├── ByteBufferPool.kt        # Efficient buffer management
│       ├── Packet.kt                # Packet representation
│       ├── TCB.kt                   # TCP Control Block
│       ├── TCPInput.kt              # TCP downstream handler
│       ├── TCPOutput.kt             # TCP upstream handler
│       ├── UDPInput.kt              # UDP downstream handler
│       └── UDPOutput.kt             # UDP upstream handler
└── ui/
    ├── screens/
    │   ├── DashboardScreen.kt       # Main dashboard
    │   ├── AppDetailScreen.kt       # Per-app detail view
    │   └── ReportScreen.kt          # Security report view
    ├── viewmodel/
    │   ├── DashboardViewModel.kt    # Dashboard state management
    │   └── AppDetailViewModel.kt    # App detail state management
    └── theme/
        ├── Color.kt
        ├── Theme.kt
        └── Type.kt
```

---

## 🚀 Getting Started

### Prerequisites

- **Android Studio** Ladybug or newer
- **JDK 17+**
- **Android SDK** with API 35

### Build & Run

1. Clone the repository:
   ```bash
   git clone https://github.com/harshbpathak/Netsecure-android.git
   ```
2. Open the project in Android Studio
3. Sync Gradle and let dependencies download
4. Run on a physical device or emulator (API 24+)

> **Note:** VPN functionality works best on a physical device.

---

## 📄 License

This project is for educational and personal use.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open an issue or submit a pull request.
