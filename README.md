# 🛡️ NetSecure

**NetSecure** is an advanced Android network analyzer app that monitors and captures real-time network traffic on your device using a local VPN service. Powered by a highly-optimized native C++ backend and nDPI for Deep Packet Inspection, it gives you full visibility into which apps are making network connections, where they're connecting to, and how much data they're using — all without requiring root access.

---

## ✨ Features

- **Real-Time Traffic Capture** — Intercepts and inspects TCP/UDP packets through a high-performance local VPN tunnel powered by a Custom Native C engine.
- **Deep Packet Inspection (DPI)** — Uses nDPI for accurate protocol detection and traffic analysis.
- **Per-App Traffic Breakdown** — See exactly which apps are sending and receiving data.
- **Connection Logging** — Detailed logs of every connection with destination IP, port, and protocol.
- **Dashboard Overview** — Clean, at-a-glance view of network activity across all apps.
- **No Root Required** — Uses Android's VPN Service API combined with native packet processing.

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Language** | Kotlin (App layer), C/C++ (Native engine) |
| **UI** | Jetpack Compose + Material 3 |
| **Architecture** | MVVM (ViewModel + Repository) + JNI Bridge |
| **Packet Engine** | Custom native core (`zdtun`, `libpcap`) |
| **DPI Engine** | nDPI |
| **Min SDK** | Android 7.0 (API 24) |

---

## 📁 Project Structure

```
app/src/main/
├── java/com/example/netsecure/
│   ├── MainActivity.kt                  # Entry point
│   ├── CaptureService.kt                # VPN Service & JNI Bridge
│   ├── NetSecureApp.kt                  # Application class
│   ├── data/
│   │   ├── ConnectionsRegister.kt       # High-performance ring buffer for native events
│   │   └── TrafficRepository.kt         # Data layer for traffic records
│   ├── model/                           # JNI-compatible data models
│   │   ├── ConnectionDescriptor.kt      
│   │   ├── CaptureStats.kt              
│   │   └── PayloadChunk.kt              
│   └── ui/
│       ├── screens/                     # Compose UI screens
│       ├── viewmodel/                   # State management
│       └── theme/                       # Compose theming
└── jni/
    ├── core/                            # Main native capture engine
    ├── common/                          # Shared native utilities
    ├── pcapd/                           # libpcap daemon
    └── third_party/                     # Third party C libraries
submodules/
├── nDPI/                                # Deep Packet Inspection library
├── libpcap/                             # Packet capture library
├── zdtun/                               # TUN interface networking
└── MaxMind-DB-Reader-java/              # GeoIP resolution
```

---

## 🚀 Getting Started

### Prerequisites

- **Android Studio** (Ladybug or newer recommended)
- **JDK 17+**
- **Android SDK** with API 36
- **Android NDK** `28.2.13676358` (will be downloaded automatically by Gradle, but required for native build)
- **CMake**

### Build & Run

1. Clone the repository with submodules:
   ```bash
   git clone --recurse-submodules https://github.com/harshbpathak/Netsecure-android.git
   ```
   *(If you already cloned without submodules, run `git submodule update --init --recursive`)*

2. Open the project in Android Studio.
3. Sync Gradle and let dependencies download (including the NDK if not present).
4. Run on a physical device or emulator (API 24+).

> **Note:** VPN functionality and native routing work best on a physical Android device. Due to Android restrictions, the emulator might have limited networking capabilities depending on the setup.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to open an issue or submit a pull request.
