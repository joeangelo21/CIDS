# Cognitive Network Sentinel (Cognitive-Network-Sentinel)

A high-performance, production-grade passive network monitor and security auditing tool engineered in C++17. It specializes in real-time per-host telemetry, ARP/NDP spoofing mitigation, and gateway integrity verification using `libpcap`.

## 🛡️ Key Features

- **Passive Link-Layer Auditing:** Intercepts Ethernet frames without injecting traffic, ensuring absolute stealth across network segments.
- **Gateway Integrity Enforcement:** Continuously monitors ARP and IP packets originating from the gateway to detect potential ARP spoofing and Man-in-the-Middle (MITM) attacks.
- **Robust IPv6 & NDP Protection:** Implements strict RFC 4861 compliance checks (such as Hop Limit 255 validation) and defends against Rogue Router Advertisements (Rogue RA / mitm6) and NDP spoofing.
- **Memory-Safe LRU Host Tracking:** Utilizes a combined hash map and Least Recently Used (LRU) eviction policy (`MAX_HOSTS = 8192`) to prevent memory exhaustion and Denial of Service (DoS) attacks via IP spoofing floods.
- **Adaptive Rate Limiting & Cooldowns:** Built-in rate controllers suppress log flooding and alert noise during high-volume network events or active flooding scenarios.
- **Advanced Security Hardening:** Features automatic privilege dropping (`setuid`/`setgid` to unprivileged users post-initialization) combined with `prctl(PR_SET_NO_NEW_PRIVS)` to mitigate escalation risks.
- **Fuzzing Harness Support:** Includes native conditional compilation directives (`#ifdef SENTINEL_FUZZ`) compatible with `libFuzzer` for continuous robustness validation.

## 🚀 Architecture & Workflow

1. **Initialization & Privilege Binding:** Opens the live capture interface or offline PCAP file, compiles optimized Berkeley Packet Filters (BPF), and binds necessary low-level sockets with elevated privileges.
2. **Privilege Reduction:** Instantly drops root privileges to an unprivileged context to enforce strict principle of least privilege.
3. **Packet Ingestion & Parsing:** Continuously captures frames using non-blocking I/O (`poll()` integration), parsing Ethernet, VLAN tags, IPv4, IPv6, and ICMPv6/NDP headers.
4. **Telemetry & Anomaly Scoring:** Evaluates per-host packet rates using Exponentially Weighted Moving Averages (EWMA) and dynamic trust scoring, triggering suppressed alerts upon threshold breaches.

## 🛠️ Usage & Compilation

### Compilation (Hardened Build)

```bash
g++ -std=c++17 -O2 -Wall -Wextra -Wshadow -Wconversion -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now sentinel.cpp -o sentinel -lpcap

Execution

    Live Capture (Auto Interface Detection):
    Bash

    sudo ./sentinel

    Live Capture with Explicit Gateway and PPS Limits:
    Bash

    sudo ./sentinel -i eth0 -g 192.168.1.1 -p 1500 -v

    Offline PCAP Replay Analysis:
    Bash

    ./sentinel -r capture_sample.pcap -g 192.168.1.1

📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
