# Zeek Lab Report

## Overview
This report documents my practice and findings while working with **Zeek** in the TryHackMe SOC Level 1 path.  
The objective was to analyze network traffic from `.pcap` files using Zeek, extract meaningful indicators, and practice filtering logs with `zeek-cut` and UNIX utilities (`sort`, `uniq`, `grep`).

---

## Environment
- **Platform**: TryHackMe (Zeek room)  
- **Tool**: Zeek  
- **Dataset**: Provided `.pcap` files with simulated network activity  

---

## Tasks

### Task 1 – Generate Zeek Logs
- Command: `zeek -r traffic.pcap`  
- Output: multiple log files (`conn.log`, `dns.log`, `http.log`, `ssl.log`, etc.)  

**Goal**: Understand how Zeek parses raw PCAP data into structured logs.  

---

### Task 2 – Connection Analysis
- File analyzed: `conn.log`  
- Command:  
  ```bash
  cat conn.log | zeek-cut id.orig_h id.resp_h proto service duration

    Extracted source and destination IPs, protocols, services, and session durations.

Insight: Identified suspicious connections with long-lived sessions.
Task 3 – DNS Requests

    File analyzed: dns.log

    Command:

    cat dns.log | zeek-cut query qtype_name | sort | uniq -c | sort -nr

    Listed unique DNS queries and frequency.

Insight: Found repeated queries to suspicious domains suggesting C2 beaconing.
Task 4 – HTTP Traffic

    File analyzed: http.log

    Command:

    cat http.log | zeek-cut id.orig_h host uri | grep ".exe"

    Extracted URLs and identified potential malicious .exe download attempts.

Task 5 – SSL/TLS Certificates

    File analyzed: ssl.log

    Command:

    cat ssl.log | zeek-cut id.resp_h subject issuer

    Verified certificates to detect self-signed or suspicious issuers.

Conclusion

The Zeek lab reinforced the ability to:

    Parse .pcap files into structured logs.

    Use zeek-cut effectively with UNIX pipelines to filter and analyze data.

    Identify IoCs such as suspicious domains, downloads, and anomalous connections.

This knowledge is foundational for SOC workflows, where Zeek serves as a key tool for network forensics and threat detection.

**Made by: Xavier Mota**
**19/08/2025**
