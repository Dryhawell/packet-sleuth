# PacketSleuth — Network Traffic Analyzer

PacketSleuth is an offline, defensive network traffic analyzer. It will read PCAP and PCAPNG captures, identify protocols from packet layers, calculate traffic statistics, flag suspicious patterns with explainable rules, and write local reports.

This repository is an educational Blue Team project. It analyzes captures you already have. It does not capture live traffic, decrypt TLS, upload packets, or contact external reputation services.

**Current phase: 5 — protocol analysis.** The application can read a capture and normalize Ethernet through TCP/UDP, plus DNS, plaintext HTTP, and visible TLS metadata. Statistics, detection, and reports are not implemented yet.

## Why this project exists

Network defenders spend much of their time answering a simple question: what happened on the wire? A packet capture is the evidence. PacketSleuth is a small, readable tool for practicing that work: open a capture, normalize what is actually present, and explain findings without over-claiming.

## What you practice

- Python packages, dataclasses, type hints, logging, and tests
- TCP/IP and the OSI model, applied to real packet layers
- The difference between a port number and a confirmed protocol
- Defensive detection, evidence, and false positives

## PCAP and PCAPNG

A **packet** is one unit of network data. A **frame** is that unit as seen on a link, often including Ethernet addressing.

A **PCAP** file is a recording of frames or packets with timestamps. **PCAPNG** (PCAP Next Generation) is a newer container. It can store the same packets plus extra metadata, such as multiple interfaces. PacketSleuth will accept both. A `.pcap` extension alone does not prove the file is valid PCAP.

## Architecture

Later phases follow this flow. The entry point, logging, data models, PCAP reader, and packet normalizer exist today. DNS, HTTP, and TLS fields are filled only when those payloads are visible in the frame.

```
PCAP / PCAPNG
      |
      v
 PCAP Reader
      |
      v
 Packet Parser
      |
      v
 Protocol Identification
      |
      v
 Traffic Analyzer
      |
      v
 Detection Engine
      |
      v
 Alert Manager
     / \
    v   v
Reporting  CLI
```

Each stage will stay independent. Raw Scapy packets will not be mixed into the normalized models used by statistics and detection.

## Project structure

```
packet-sleuth/
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── packetsleuth/
│   ├── __init__.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alert.py
│   │   ├── analysis_result.py
│   │   ├── connection.py
│   │   ├── enums.py
│   │   ├── packet.py
│   │   └── validation.py
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── file_validator.py
│   │   └── pcap_reader.py
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── dns_parser.py
│   │   ├── http_parser.py
│   │   ├── packet_parser.py
│   │   ├── protocol_parser.py
│   │   └── tls_parser.py
│   └── utils/
│       ├── __init__.py
│       └── logger.py
├── data/
│   ├── samples/
│   └── reports/
├── logs/
└── tests/
    ├── __init__.py
    ├── test_models.py
    ├── test_pcap_reader.py
    ├── test_packet_parser.py
    ├── test_dns_parser.py
    └── test_http_parser.py
```

The reader checks the file header and iterates raw packets. The parser turns each frame into a `Packet` and names a protocol only when its header or payload is present. Statistics, detection, and the command-line interface are added in their own phases.

## Requirements

- Windows, macOS, or Linux
- Python 3.12 or newer
- No administrator rights for this phase
- No live capture driver (Npcap/WinPcap) for the offline MVP

## Installation

From PowerShell, in the project directory:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`scapy` parses captures in later phases. `pytest` runs the model tests. Pandas, Matplotlib, Streamlit, and Rich are intentionally omitted.

## Usage

```powershell
python main.py
```

Expected behavior: a short status message on standard output, and a startup line in `logs/packetsleuth.log`.

There is no `analyze` command yet.

## Data models

Normalized records live in `packetsleuth.models`:

- `Packet` — one frame, with missing layers left empty
- `Connection` — one bidirectional TCP or UDP flow
- `Alert` — an explainable finding with evidence and a recommendation
- `AnalysisResult` — the records collected for one capture

These objects do not contain raw payloads, cookies, or credentials. A risk score can be stored only together with a written explanation. Scoring itself is a later phase.

## Reading a capture

There is still no `analyze` command. The reader is available to Python:

```python
from packetsleuth.capture import CaptureReader

with CaptureReader("data/samples/sample.pcap") as capture:
    for frame in capture:
        print(frame.packet_number, frame.timestamp)
    print(capture.file_format, capture.packet_count, capture.issues)
```

`.pcap` and `.pcapng` are both accepted. The first bytes of the file choose the reader. A matching extension is checked, but it is not treated as proof. Compressed captures are rejected. The source file is opened read-only.

## Packet parsing

```python
from packetsleuth.capture import CaptureReader
from packetsleuth.parsers import parse_frames

with CaptureReader("data/samples/sample.pcap") as capture:
    for packet in parse_frames(capture):
        print(packet.packet_number, packet.protocol.value, packet.source_ip, packet.destination_port)
```

The parser reads Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, and ICMPv6 from the decoded headers. DNS is recognized from a DNS message, plaintext HTTP from its start line, and TLS from a TLS record. Port 53 does not become DNS, and port 443 does not become TLS. An ICMP error keeps its own addresses. A TCP header quoted inside that error is not treated as this frame's transport. The first network header is kept when one IP packet carries another.

TCP flag bits already observed on the header stay on the packet: SYN, ACK, FIN, RST, PSH, and URG. A single SYN is not a scan. Cookie and Authorization headers are not copied into the record. TLS application data is not decrypted. A ClientHello can show the server name; a capture that starts later will not, and that absence is not treated as a flaw.

## Testing

From the project directory, with the virtual environment active:

```powershell
python -m pytest
```

## Privacy and security

- Analysis stays on the local machine.
- The tool does not upload captures or send packet contents anywhere.
- Source capture files will not be modified.
- Payloads, credentials, cookies, and authorization headers will not be printed by default.
- Live packet capture is out of scope until a later, explicit release.

## Responsible use

Use PacketSleuth on captures you own or are authorized to examine. The project does not intercept traffic, inject packets, scan networks, exploit systems, or decrypt encrypted communications.

## License

MIT. See [LICENSE](LICENSE).
