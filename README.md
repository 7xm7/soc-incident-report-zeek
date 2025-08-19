# Zeek Exercises – Incident Report

## Overview  
This report documents the analysis performed in the TryHackMe **Zeek Exercises** room. It covers detection of anomalous DNS activity, phishing attempts, and Log4j exploitation using generated logs and command line analysis.

---

## Task 1 – Anomalous DNS

- **Objective:** Verify if the "Anomalous DNS Activity" alert is a true positive.
- **Actions:**
  - Ran Zeek on the `dns-tunneling.pcap` file:
    ```bash
    zeek -C -r dns-tunneling.pcap
    ```
  - Counted AAAA (IPv6) DNS records:
    ```bash
    cat dns.log | zeek-cut qtype_name | grep "AAAA" | wc -l
    ```
  - Checked longest connection duration in `conn.log`:
    ```bash
    cat conn.log | zeek-cut duration | sort -n | tail -n 1
    ```
  - Counted unique domain queries:
    ```bash
    cat dns.log | zeek-cut query | awk -F. '{print $(NF-1)"."$NF}' | sort -u | wc -l
    ```
  - Identified the anomalous source host IP:
    ```bash
    cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | head -n 1
    ```

- **Findings:**
  - Number of AAAA (IPv6) records: **320**
  - Longest connection duration: **9.420791 seconds**
  - Number of unique domain queries: **6**
  - Suspicious source IP: **10.20.57.3**

---

## Task 2 – Phishing Attempt

- **Objective:** Confirm phishing activity in the traffic.
- **Actions:**
  - Located the suspicious source IP (defanged):
    ```bash
    cat conn.log | zeek-cut id.orig_h | sort -u
    ```
  - Found the hosting domain for malicious downloads (defanged):
    ```bash
    cat http.log | zeek-cut host uri
    ```
  - Extracted file hash and MIME type from `files.log`:
    ```bash
    cat files.log | zeek-cut md5 mime_type | grep "word"
    ```
  - Queried VirusTotal to identify file type: **VBA**
  - Extracted and identified `.exe` file behavior, including contacted domain:
    - Malicious executable name: **knr.exe**
    - Contacted domain: **hopto[.]org**

---

## Task 3 – Log4j Exploitation

- **Objective:** Check for exploitation attempts of the Log4j vulnerability.
- **Actions:**
  - Ran Zeek with the detection script:
    ```bash
    zeek -C -r log4shell.pcapng detection-log4j.zeek
    ```
  - Counted signature hits in `signatures.log`:
    ```bash
    cat signatures.log | zeek-cut uid | wc -l
    ```
  - Identified scanning tool used:
    ```bash
    cat http.log | zeek-cut user_agent
    ```
  - Found exploit file extension in URI:
    ```bash
    cat http.log | zeek-cut uri
    ```
  - Extracted base64 payload and decoded file name:
    ```bash
    cat log4j.log | zeek-cut uri | grep "Base64" | awk -F/ '{print $NF}' | base64 -d
    ```

- **Findings:**
  - Number of signature hits: **3**
  - Scanning tool detected: **nmap**
  - Extension of exploit file: `.class`
  - Name of the file created **pwned**

---

## Conclusion  

This lab confirmed the following via Zeek analysis:

- Anomalous DNS activity and tunneling detected.
- Phishing attempts and malicious downloads identified.
- Evidence of Log4j exploitation attempts captured.
---

**Made by: Xavier Mota**

**19/08/2025**
