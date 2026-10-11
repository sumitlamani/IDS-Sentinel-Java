# IDS//SENTINEL — Distributed Intrusion Detection System (Java Edition)

A high-performance, distributed, web-based Intrusion Detection & Prevention System built with **Java 21**, **Spring Boot**, and **Pcap4J**, featuring a dark terminal-style SOC dashboard, real-time threat streaming, and a multi-node agent architecture.

---

## Features

- **Distributed Edge Agent Architecture** — Deploy lightweight sniffing agents on remote servers and edge nodes that report back to a central Spring Boot controller.
- **Deep Packet Inspection (Pcap4J)** — Real-time Layer 2/3/4 packet inspection directly from raw network interfaces.
- **Multi-Vector Attack Detection Engine**:
  - **Port Scanning** — Detects horizontal and vertical port scanning with sliding-window state tracking.
  - **TCP Stealth Scans** — Flags classic Nmap stealth probes including **Xmas Scans** (FIN+PSH+URG), **NULL Scans** (0 flags), and **FIN Scans**.
  - **TCP SYN Flood (DDoS)** — Catches high-volume unacknowledged SYN packets.
  - **LAND Attack** — Flags spoofed packets with identical source and destination IP and port.
  - **ICMP Ping Storm** — Detects ICMP flood denial-of-service attempts.
  - **UDP Floods** — Detects aggressive UDP packet bursts.
  - **DNS Tunneling & Exfiltration** — Flags suspicious oversized DNS payloads ($>1200$ bytes) and query bursts on port 53.
  - **ARP Cache Poisoning** — Detects Man-in-the-Middle MAC spoofing attacks.
- **Real-Time SOC Dashboard**:
  - Live **Server-Sent Events (SSE)** alert feed with zero page refresh.
  - Interactive **Global Threat Map** powered by dark Esri vector canvas (no API keys required).
  - Protocol distribution mix (TCP, UDP, ICMP) and Top Talkers traffic analysis with GeoIP country flags.
  - Dynamic threshold configuration modal with persistent SQLite storage.
- **Dual Operating Modes**:
  - **Live Mode** — Sniffs actual packets from your physical network interface.
  - **Demo Simulation Mode (`--demo`)** — Injects realistic attack scenarios from global threat IPs for presentations, testing, and interviews.

---

## Project Structure

```
ids-java/
├── pom.xml                         # Root Maven POM (Java 21, Spring Boot 3.2.3)
├── Start_Java_Dashboard.command    # One-click startup for Dashboard (macOS/Linux)
├── Start_Java_Agent.command        # One-click startup for Agent (macOS/Linux)
├── Start_Java_Dashboard.bat        # One-click startup for Dashboard (Windows)
├── Start_Java_Agent.bat            # One-click startup for Agent (Windows)
├── server/                         # Central Controller & Dashboard Server
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/ids/server/    # Controllers, Security, SSE Stream, Database
│       └── resources/              # HTML Templates, Static Assets, application.properties
└── agent/                          # Network Sniffing & Detection Agent
    ├── pom.xml
    └── src/main/java/com/ids/agent/
        ├── AgentApplication.java   # Pcap4J loop, telemetry sync, demo simulator
        └── AttackDetector.java     # Stateful heuristic detection engine
```

---

## Quick Start

### Prerequisites
- **Java 21** or higher (`java -version`)
- **Maven 3.8+** (`mvn -v`)
- **Packet Capture Drivers**:
  - **macOS / Linux**: Built-in `libpcap`
  - **Windows**: Install [Npcap](https://npcap.com/) (check *"Install Npcap in WinPcap API-compatible Mode"*)

---

### 1. Start the Central Dashboard

```bash
# Build the project and run the server
mvn clean install -DskipTests
mvn -pl server spring-boot:run
```
*(Or simply double-click `Start_Java_Dashboard.command` on macOS or `Start_Java_Dashboard.bat` on Windows)*

Open your browser to: **http://localhost:8080**

**Default Credentials:**
- **Username:** `admin`
- **Password:** `admin123`

---

### 2. Run the IDS Sniffing Agent

The agent requires root / administrator privileges to access raw network sockets:

#### On macOS / Linux:
```bash
# Build the agent jar
mvn -pl agent compile package -DskipTests

# Run Live Capture (Sniffs actual network packets)
sudo java -jar agent/target/agent-1.0-SNAPSHOT-jar-with-dependencies.jar

# OR Run in Demo Attack Mode (Injects simulated attacks for testing)
sudo java -jar agent/target/agent-1.0-SNAPSHOT-jar-with-dependencies.jar --demo
```
*(Or run `./Start_Java_Agent.command` and select Live or Demo mode)*

#### On Windows (Run Command Prompt / PowerShell as Administrator):
```cmd
java -jar agent\target\agent-1.0-SNAPSHOT-jar-with-dependencies.jar
```
*(Or right-click `Start_Java_Agent.bat` and choose **Run as Administrator**)*

---

## REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web SOC Analyst Dashboard UI |
| `POST` | `/login` | Analyst authentication |
| `GET` | `/api/agents` | List connected agent nodes |
| `POST` | `/api/agents` | Register new agent and generate API key |
| `POST` | `/api/agent/sync` | Agent telemetry and alert synchronization |
| `GET` | `/api/alerts` | Query historical alerts |
| `GET` | `/api/stream` | Server-Sent Events (SSE) live alert stream |
| `GET` | `/api/config` | Fetch active detection thresholds |
| `POST` | `/api/config` | Update global detection thresholds dynamically |

---

## License
MIT License. Created for advanced network monitoring and intrusion detection research.
