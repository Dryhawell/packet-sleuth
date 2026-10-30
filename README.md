# PacketSleuth — Network Traffic Analyzer

PacketSleuth is an offline, defensive network traffic analyzer. It will read PCAP and PCAPNG captures, identify protocols from packet layers, calculate traffic statistics, flag suspicious patterns with explainable rules, and write local reports.

This repository is an educational Blue Team project. It analyzes captures you already have. It does not capture live traffic, decrypt TLS, upload packets, or contact external reputation services.

**Current phase: 1 — project initialization.** The application starts and writes a log. Packet reading, parsing, statistics, detection, and reports are not implemented yet.

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

Later phases follow this flow. Only the entry point and logging exist today.

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
│   └── utils/
│       ├── __init__.py
│       └── logger.py
├── data/
│   ├── samples/
│   └── reports/
├── logs/
└── tests/
```

Parsers, analysis, detection, and the command-line interface are added in their own phases. Empty directories are kept with `.gitkeep` so Git can track them.

## Requirements

- Windows, macOS, or Linux
- Python 3.12 or newer
- No administrator rights for this phase
- No live capture driver (Npcap/WinPcap) for the offline MVP

## Installation

From PowerShell, in the project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

`scapy` parses captures in later phases. `pytest` runs the test suite when tests exist. Pandas, Matplotlib, Streamlit, and Rich are intentionally omitted.

## Usage

```powershell
python main.py
```

Expected behavior: a short status message on standard output, and a startup line in `logs/packetsleuth.log`.

There is no `analyze` command yet.

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
