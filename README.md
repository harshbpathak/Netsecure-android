# 🛡️ NetSecure

**NetSecure** is an Android network security and privacy monitoring app that captures real-time traffic via a local VPN, classifies it by app and category, performs Deep Packet Inspection with nDPI, runs a local Intrusion Detection System, and submits suspicious observables to an IntelOwl threat intelligence backend — all without root access.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android-green?logo=android" />
  <img src="https://img.shields.io/badge/Min%20SDK-24%20(Android%207.0)-blue" />
  <img src="https://img.shields.io/badge/Language-Kotlin%20%7C%20C-purple" />
  <img src="https://img.shields.io/badge/UI-Jetpack%20Compose-blue?logo=jetpackcompose" />
  <img src="https://img.shields.io/badge/License-GPL--3.0-red" />
</p>

---

## Table of Contents

- [Features](#-features)
- [Screenshots](#-screens)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [IntelOwl Setup](#-intelowl-integration-setup)
- [How It Works](#-how-it-works)
- [Security & Privacy](#-security--privacy)
- [License](#-license)
- [Contributing](#-contributing)

---

## ✨ Features

### Traffic Capture & Analysis
- **Real-Time Packet Capture** — Intercepts all TCP/UDP traffic through a high-performance local VPN tunnel powered by a native C engine with `zdtun` and `libpcap`.
- **Deep Packet Inspection** — nDPI identifies 300+ application-layer protocols (TLS.Facebook, QUIC.YouTube, etc.) for accurate traffic classification.
- **Per-App Traffic Breakdown** — Resolves every connection to the originating app via UID mapping, showing per-app request counts, data in/out, and connection details.
- **Traffic Categorization** — Automatically classifies all connections into 10 categories: Social Media, Streaming, Ads & Trackers, Cloud, Messaging, Gaming, Shopping, System, CDN, and Other — using a three-stage pipeline (nDPI protocol → domain suffix → IP heuristics) with 300+ classification rules.
- **Connection Details** — Every connection logs source/destination IPs and ports, L7 protocol, SNI/domain, bytes transferred, duration, encryption status, and timestamps.
- **CSV Export** — Export all captured connections to a CSV file in your Downloads folder.

### Threat Intelligence
- **IntelOwl Integration** — Automatically submits suspicious IPs and domains to a self-hosted IntelOwl instance for analysis using configurable analyzers (AbuseIPDB, OTX, GreyNoise, MalwareBazaar).
- **Weighted Threat Scoring** — Aggregates results from multiple analyzers with weighted scoring (AbuseIPDB 40%, OTX 30%, MalwareBazaar 20%, GreyNoise 10%) and classifies severity as Clean, Low, Medium, High, or Critical.
- **Priority Scan Queue** — Intelligent queueing system that prioritizes blacklisted IPs, unknown protocols, and non-standard ports while skipping private IPs and known-safe endpoints.
- **Threat Alerts** — Real-time dismissible alert banners for HIGH and CRITICAL findings on the dashboard.

### Local Intrusion Detection
- **Signature-Based IDS** — Scans unencrypted payloads against 11 regex-based signatures covering: cryptominer user-agents, IRC botnet commands, shell download chains, cleartext password exposure, SQL injection attempts, DNS queries to mining pools, malware C2 domains, DGA domains, Tor/onion routing, and phishing domains.

### Privacy & Reporting
- **Privacy Report** — Automated privacy concern detection: high tracker activity, excessive data transfer, suspicious request rates, and tracker domain exposure.
- **Top Talkers** — Identifies the top 5 apps by data volume.
- **Threat Intelligence History** — Searchable, filterable table of all scanned observables with severity breakdown, per-analyzer results, and score visualizations.

### System
- **Persistent Logging** — Dual-output logger (in-memory ring buffer + 1 MB rotating log file) with 5 levels and 4 tag categories, shareable via Android share sheet.
- **No Root Required** — Uses Android's VPN Service API with split routing for transparent packet capture.
- **Dark Cybersecurity Theme** — Navy/cyan/purple Material 3 dark theme designed for security monitoring.

---

## 📱 Screens

| Screen | Description |
|--------|-------------|
| **Dashboard** | Summary cards (apps, requests, data in/out), category breakdown bar graph, per-app traffic cards with threat severity indicators, start/stop FAB, CSV export |
| **App Detail** | Per-app deep dive with connection list (up to 300), L7 protocol chips, expandable connection details, per-connection IntelOwl threat reports |
| **Report** | Privacy report with overall summary, data category breakdown, auto-generated privacy concern alerts, top talkers, threat intel summary |
| **Threat Intelligence** | Full threat history with severity distribution chart, searchable observable table, per-analyzer result expansion (AbuseIPDB, OTX, GreyNoise, MalwareBazaar) |
| **IntelOwl Settings** | Server URL, encrypted API token, TLP level selection, analyzer picker, cache TTL and concurrency sliders, connection test |
| **Logs** | Live auto-scrolling log viewer with level/category/text filters, share/copy/save/clear actions |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Jetpack Compose UI                    │
│  Dashboard · App Detail · Report · Threat Intel · Logs  │
├─────────────────────────────────────────────────────────┤
│              ViewModels (StateFlow + MVVM)               │
├──────────────────────┬──────────────────────────────────┤
│   TrafficRepository  │      ThreatIntelRepository       │
│   TrafficClassifier  │  ScanQueue · ThreatCache · IDS   │
├──────────────────────┼──────────────────────────────────┤
│  ConnectionsRegister │     IntelOwl API (Retrofit)      │
│   (Ring Buffer 8K)   │   EncryptedSharedPreferences     │
├──────────────────────┴──────────────────────────────────┤
│              CaptureService (VPN Service)                │
│                    JNI Bridge                            │
├─────────────────────────────────────────────────────────┤
│                 Native C Engine                          │
│     pcapdroid core · zdtun · nDPI · libpcap             │
│  TUN fd → Packet Loop → DPI Classification → Callbacks  │
└─────────────────────────────────────────────────────────┘
```

**Data flow:**
1. `CaptureService` creates a TUN interface via VPN Service and passes the file descriptor to the native engine.
2. The native C core (`pcapdroid.c`) runs a packet loop using `zdtun` for TCP/UDP routing and `nDPI` for protocol identification.
3. Connection data flows back to Kotlin via JNI callbacks → `ConnectionsRegister` (ring buffer) → `TrafficRepository` (classification & aggregation) → ViewModels → Compose UI.
4. In parallel, `ThreatIntelRepository` extracts observables from connections, queues them by priority, batch-submits to IntelOwl every 5s, and polls for results every 10s.
5. The `SignatureScanner` runs locally on unencrypted payloads and injects findings into the threat alert pipeline.

---

## 🔧 Tech Stack

| Layer | Technology | Version |
|-------|------------|---------|
| **Language** | Kotlin (app) · C (native engine) | — |
| **UI** | Jetpack Compose + Material 3 | BOM 2024.09.00 |
| **Navigation** | Jetpack Navigation Compose | 2.8.9 |
| **Architecture** | MVVM (ViewModel + StateFlow + Repository) | — |
| **Networking** | Retrofit 2 + OkHttp | 2.11.0 / 4.12.0 |
| **JSON** | Gson | 2.11.0 |
| **Async** | Kotlin Coroutines | 1.8.1 |
| **Security** | EncryptedSharedPreferences (AES-256-GCM) | 1.1.0-alpha06 |
| **Native Engine** | PCAPdroid core via JNI | NDK 28.2 |
| **DPI** | nDPI | submodule |
| **Tunneling** | zdtun | submodule |
| **Packet Capture** | libpcap | submodule (1.10.6) |
| **GeoIP** | MaxMind DB Reader Java | submodule |
| **Build** | Gradle (Kotlin DSL) · CMake 3.22.1 | AGP 9.0.1 |
| **Min SDK** | Android 7.0 (API 24) | |
| **Target SDK** | API 36 | |

---

## 📁 Project Structure

```
app/src/main/
├── java/com/example/netsecure/
│   ├── NetSecureApp.kt                  # Application class — initializes logger & IntelOwl config
│   ├── MainActivity.kt                  # Single-activity Compose host with bottom navigation
│   ├── CaptureService.kt               # VPN foreground service + JNI bridge
│   │
│   ├── navigation/
│   │   └── NavGraph.kt                 # 6 routes: Dashboard, AppDetail, Report, ThreatIntel, Settings, Logs
│   │
│   ├── ui/
│   │   ├── screens/
│   │   │   ├── DashboardScreen.kt       # Main dashboard with traffic overview
│   │   │   ├── AppDetailScreen.kt       # Per-app connection inspector
│   │   │   ├── ReportScreen.kt          # Privacy report & analysis
│   │   │   ├── ThreatIntelligenceScreen.kt  # Threat intel history & search
│   │   │   ├── IntelOwlSettingsScreen.kt    # IntelOwl configuration
│   │   │   └── LogsScreen.kt           # Live system log viewer
│   │   ├── viewmodel/
│   │   │   ├── DashboardViewModel.kt    # Traffic state, capture control, threat summary
│   │   │   ├── AppDetailViewModel.kt    # Per-app connection filtering & threat lookup
│   │   │   ├── ThreatIntelViewModel.kt  # Observable table, severity stats, remote job fetch
│   │   │   └── LogsViewModel.kt         # Log polling, filtering, export
│   │   └── theme/                       # Dark cybersecurity theme (Color, Theme, Type)
│   │
│   ├── data/
│   │   ├── TrafficRepository.kt         # Traffic aggregation & app classification
│   │   ├── TrafficClassifier.kt         # 3-stage classifier (nDPI → domain → IP heuristics)
│   │   ├── ConnectionsRegister.kt       # Thread-safe ring buffer (8192 slots)
│   │   ├── ThreatIntelRepository.kt     # IntelOwl orchestration & result scoring
│   │   ├── ScanQueue.kt                 # Priority-based scan queue (max 500)
│   │   ├── ThreatCache.kt              # LRU cache (2000 entries) with TTL
│   │   ├── SignatureScanner.kt          # Local IDS with 11 regex signatures
│   │   └── model/                       # AppTrafficInfo, TrafficCategory, ThreatReport, etc.
│   │
│   ├── model/                           # JNI-bridged models
│   │   ├── ConnectionDescriptor.kt      # Per-connection state (IPs, ports, L7 proto, SNI, payload)
│   │   ├── ConnectionUpdate.kt          # Incremental connection updates from native
│   │   ├── CaptureStats.kt             # Global capture statistics
│   │   ├── PayloadChunk.kt             # Raw payload bytes with metadata
│   │   ├── BlacklistDescriptor.kt      # IP/domain blacklist entries
│   │   └── MatchList.kt                # Firewall/whitelist rules
│   │
│   ├── network/
│   │   ├── IntelOwlApiService.kt        # Retrofit interface (6 endpoints)
│   │   ├── IntelOwlConfig.kt            # Encrypted config with AndroidKeyStore
│   │   └── model/AnalysisModels.kt      # API request/response models
│   │
│   └── logging/
│       └── NetSecureLogger.kt           # Dual-output logger (memory + file)
│
├── jni/
│   ├── CMakeLists.txt                   # Builds libcapture.so, libndpi.so, libzdtun.so
│   ├── core/                            # Packet processing loop, VPN/PCAP capture, nDPI integration
│   ├── common/                          # JNI utilities, UID resolution
│   ├── pcapd/                           # Root capture daemon (alternative mode)
│   └── third_party/                     # libchash (hash table)
│
└── res/                                 # Drawables, icons, strings, themes

submodules/
├── nDPI/                                # Deep Packet Inspection library
├── zdtun/                               # TCP/UDP tunnel library
├── libpcap/                             # Packet capture library
└── MaxMind-DB-Reader-java/              # GeoIP database reader
```

---

## 🚀 Getting Started

### Prerequisites

- **Android Studio** Ladybug or newer
- **JDK 17+**
- **Android SDK** with API 36
- **Android NDK** `28.2.13676358` (auto-downloaded by Gradle)
- **CMake** 3.22.1+

### Build & Run

1. **Clone with submodules:**
   ```bash
   git clone --recurse-submodules https://github.com/harshbpathak/Netsecure-android.git
   ```
   If already cloned:
   ```bash
   git submodule update --init --recursive
   ```

2. Open in Android Studio and sync Gradle.

3. Run on a physical device (API 24+).

> **Note:** VPN capture and native routing work best on a physical device. Emulators may have limited networking depending on the configuration.

### Permissions

The app requests these permissions at install or runtime:

| Permission | Why |
|------------|-----|
| `INTERNET` | IntelOwl API calls |
| `ACCESS_NETWORK_STATE` | Detect connectivity changes |
| `ACCESS_WIFI_STATE` | Wi-Fi state detection |
| `FOREGROUND_SERVICE` | Keep VPN capture alive in background |
| `POST_NOTIFICATIONS` | Show capture notification (Android 13+) |
| `QUERY_ALL_PACKAGES` | Resolve connection UIDs to app names and icons |

---

## 🔌 IntelOwl Integration Setup

NetSecure integrates with [IntelOwl](https://github.com/intelowlproject/IntelOwl) — an open-source threat intelligence platform — to analyze suspicious IPs and domains observed in your traffic.

### Setup Steps

1. Deploy an IntelOwl instance (see [IntelOwl docs](https://intelowl.readthedocs.io/)).
2. In NetSecure, go to **Dashboard → ⚙️ Settings**.
3. Enter your **Server URL** and **API Token**.
4. Hit **Test Connection** to verify.
5. Select your preferred **TLP level** and **analyzers**.
6. Enable the IntelOwl toggle — scanning starts automatically during capture.

### Supported Analyzers

| Analyzer | What it checks |
|----------|---------------|
| **AbuseIPDB** | IP reputation from crowd-sourced abuse reports |
| **OTXQuery** | AlienVault OTX threat pulse data |
| **GreyNoiseCommunity** | Internet-wide scan/noise classification |
| **MalwareBazaar** | Known malware indicator matching |

Results are scored with weighted aggregation and cached locally (configurable TTL) to minimize API calls.

---

## ⚙️ How It Works

### Packet Capture Pipeline

```
Android Apps
     │  (all TCP/UDP traffic)
     ▼
TUN Interface (VPN Service)
     │
     ▼
Native C Engine (libcapture.so)
  ├── zdtun: Routes packets through tunnel
  ├── nDPI: Identifies application-layer protocol
  └── Blacklist matching: Flags known-bad IPs/domains
     │
     ▼  (JNI callbacks)
ConnectionsRegister (ring buffer, 8192 slots)
     │
     ▼
TrafficRepository
  ├── UID → App resolution (PackageManager)
  ├── TrafficClassifier (300+ domain/protocol rules)
  └── Per-app aggregation
     │
     ├──▶ UI (Dashboard, App Detail, Report)
     │
     └──▶ ThreatIntelRepository
           ├── ScanQueue (priority-based, max 500)
           ├── SignatureScanner (local IDS, 11 signatures)
           ├── IntelOwl API (batch submit every 5s)
           ├── Job Poller (check results every 10s)
           ├── Weighted scoring & severity classification
           └── Alert pipeline → UI
```

### Traffic Classification Pipeline

Each connection goes through three classification stages:

1. **nDPI Protocol** — Protocol name matching (e.g., `TLS.Facebook` → Social Media)
2. **Domain Suffix** — 300+ domain rules covering all major services and tracker networks
3. **IP Heuristics** — Private IPs and well-known ports (53, 123) mapped to System category

---

## 🔒 Security & Privacy

- **Encrypted Token Storage** — IntelOwl API token protected with AES-256-GCM via `EncryptedSharedPreferences` backed by Android KeyStore.
- **Local Processing** — All packet capture and classification happens on-device. Only observables you explicitly enable are sent to IntelOwl.
- **VPN Self-Exclusion** — The app excludes itself from capture to prevent routing loops.
- **Split Routing** — Uses `0.0.0.0/1` + `128.0.0.0/1` routes instead of default route to preserve system connectivity.
- **Private IP Filtering** — RFC 1918 and link-local addresses are automatically excluded from threat scanning.
- **Rate Limiting** — Exponential backoff (5s → 60s) on API throttling to respect server limits.
- **No Data Collection** — NetSecure does not send any data to external servers other than your configured IntelOwl instance.

---

## 📄 License

This project is licensed under the [GPL-3.0 License](LICENSE).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Feel free to open an issue or submit a pull request.
