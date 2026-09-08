
# Day 3 — Practical SOC Network Investigations

## Objective

The objective of Day 3 was to move from basic protocol analysis into practical SOC investigation of suspicious network behavior.

The investigations focused on identifying abnormal communication patterns, extracting evidence from packet captures, distinguishing malicious-looking behavior from confirmed malicious activity, and applying SOC analyst reasoning.

## Lab Environment

### Systems

* Kali Linux — Analyst workstation
* Metasploitable — Controlled vulnerable laboratory host
* Wireshark — Packet capture and analysis
* Nmap — Controlled network reconnaissance
* curl — HTTP testing
* dig — DNS analysis
* Netcat (`nc`) — Controlled C2-style communication

### Network

```text
Kali Linux
192.168.56.103
     |
     | Host-only isolated network
     |
Metasploitable
192.168.56.101
```

The C2 investigation was conducted on the isolated Host-only network to prevent interaction with real external C2 infrastructure.

---

# Investigation 1 — Malicious Traffic Analysis

## Objective

Identify traffic that appears suspicious or malicious and determine whether the observed evidence is sufficient to classify it as malicious.

## Benign Baseline

I first generated normal ICMP traffic:

```bash
ping -c 10 10.0.2.2
```

Example packet:

```text
10.0.2.15 → 10.0.2.2
ICMP Echo Request
Length: 98 bytes
TTL: 64
```

This established a benign baseline.

A key SOC lesson was that suspicious traffic should be evaluated against expected network behavior rather than automatically classified as malicious.

## Controlled Suspicious HTTP Activity

I generated HTTP traffic using:

```bash
curl http://example.com
```

I then modified the HTTP User-Agent:

```bash
curl -A "Mozilla/5.0" http://example.com
curl -A "sqlmap/1.8" http://example.com
```

The captured HTTP request contained:

```text
User-Agent: sqlmap/1.8
```

## Analyst Interpretation

`sqlmap` is associated with SQL injection testing.

The User-Agent therefore represents a useful security indicator.

However:

```text
IOC ≠ Confirmed Compromise
```

The User-Agent is controlled by the client and can be deliberately changed.

Therefore, the correct SOC approach is:

```text
Indicator
   ↓
Investigate
   ↓
Correlate
   ↓
Determine Context
   ↓
Verdict
```

## Verdict

**Suspicious / security-relevant traffic generated intentionally in the lab.**

The evidence does not independently prove compromise.

---

# Investigation 2 — DNS Tunnelling

## Objective

Investigate DNS traffic for characteristics that could indicate DNS tunnelling.

## Normal DNS Baseline

I generated a normal DNS query:

```bash
dig example.com
```

Observed:

```text
Source:      10.0.2.15
Destination: 192.168.0.1
Source Port: 50290
Destination: 53
Query:       example.com
Type:        A
```

Port `53` identified the traffic as DNS.

## Repeated Subdomain Queries

I generated multiple queries:

```bash
for i in {1..20}; do dig "data$i.example.com"; done
```

The capture showed multiple DNS queries and responses.

## Random-Looking DNS Labels

I then generated random-looking labels:

```bash
for i in {1..10}; do dig "$(head -c 12 /dev/urandom | xxd -p).example.com"; done
```

Example:

```text
55fb6c4a67d7ce955b5aa295.example.com
```

The label was:

* Long
* Hexadecimal-looking
* Random
* Different from the other generated labels

## Analyst Interpretation

A single random-looking DNS label is **not sufficient evidence of DNS tunnelling**.

A stronger DNS tunnelling hypothesis would involve characteristics such as:

* Large numbers of unique subdomains
* High-entropy/random-looking labels
* Long encoded-looking labels
* Sustained query volume
* Repeated communication with the same parent domain
* Data-like information embedded in DNS labels
* Unusual query frequency

The investigation demonstrated the **indicators that an analyst would investigate**, rather than falsely classifying normal DNS traffic as tunnelling.

## Verdict

**Controlled DNS-tunnelling-like traffic characteristics demonstrated.**

No real malicious DNS tunnel was deployed.

---

# Investigation 3 — Port Scanning

## Objective

Identify and analyze TCP SYN scanning behavior.

## Nmap Scan

I generated a controlled SYN scan:

```bash
sudo nmap -sS -p 1-1000 10.0.2.2
```

## Wireshark Filter

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

The capture contained approximately 500 SYN packets.

The destination ports changed rapidly.

Example:

```text
10.0.2.15:47065
        ↓ SYN
10.0.2.2:554
```

The packet contained:

```text
Flags: 0x002
SYN: Set
ACK: Not set
```

## SYN/ACK Response Analysis

I then used:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

Approximately 10 SYN/ACK responses were observed.

Example:

```text
10.0.2.15:47065 → 10.0.2.2:445
SYN

10.0.2.2:445 → 10.0.2.15:47065
SYN/ACK
```

Port `445` is associated with SMB.

## Analyst Interpretation

The combination of:

* Large number of SYN packets
* Rapidly changing destination ports
* Small number of SYN/ACK responses

is characteristic of TCP SYN port scanning.

The behavior would be a significant SOC detection opportunity if observed unexpectedly from an internal endpoint.

Because I intentionally generated the scan with Nmap, the activity was known to be benign laboratory activity.

## Verdict

**TCP SYN port scanning / network reconnaissance detected.**

Classification:

**Benign — intentionally generated in the lab.**

---

# Investigation 4 — C2 Communication

## Objective

Identify controlled command-and-control-style communication and analyze the network evidence.

## Lab Configuration

The isolated laboratory network was:

```text
Kali:
192.168.56.103

Metasploitable:
192.168.56.101
```

Metasploitable was configured with a Netcat listener:

```bash
nc -lvnp 4444
```

Kali then generated a controlled check-in:

```bash
echo "CHECKIN-01" | nc -w 2 192.168.56.101 4444
```

## Wireshark Filter

```text
ip.addr == 192.168.56.101 && tcp.port == 4444
```

The filtered capture contained the TCP connection establishment followed by application data.

## TCP Handshake

The connection demonstrated:

```text
Kali → Metasploitable
SYN

Metasploitable → Kali
SYN/ACK

Kali → Metasploitable
ACK
```

## C2 Check-In Packet

The application-data packet showed:

```text
Source:      192.168.56.103
Destination: 192.168.56.101
Destination Port: 4444
Flags:       PSH + ACK
TCP Payload: 11 bytes
```

The captured payload was:

```text
434845434b494e2d30310a
```

Hexadecimal decoding produced:

```text
CHECKIN-01
```

The final byte:

```text
0A
```

represents a newline character.

Therefore the complete payload was:

```text
CHECKIN-01\n
```

## Server Response Analysis

The reverse-direction packet was:

```text
192.168.56.101:4444
        ↓
192.168.56.103:47348
```

The packet showed:

```text
Flags: 0x010
ACK
TCP Segment Len: 0
```

The acknowledgment number was:

```text
Ack: 12
```

The client had transmitted 11 bytes.

Therefore:

```text
Initial sequence number
1
+
Payload
11
=
Next expected byte
12
```

This confirmed that the server acknowledged receipt of the complete check-in payload.

Importantly, the reverse packet did **not** contain an application payload.

Therefore, the capture demonstrated a **C2-style check-in**, but did not demonstrate command execution or a server-to-client command payload.

## Analyst Interpretation

The observed behavior can be represented as:

```text
Client
192.168.56.103
      |
      | TCP connection
      |
      | CHECKIN-01
      ↓
Server / Listener
192.168.56.101:4444
      |
      | ACK
      ↓
Client
```

Security-relevant characteristics included:

* Persistent TCP communication endpoint
* Unusual port `4444`
* Explicit client check-in message
* Application data following TCP establishment
* Controlled client/server relationship

However, because the traffic was intentionally generated inside the isolated lab, the correct classification was **benign laboratory C2-style traffic**.

## Verdict

**Controlled C2-style check-in demonstrated.**

No real malware or external C2 infrastructure was used.

No command execution was demonstrated.

---

# Investigation Status

| Investigation        | Status   |
| -------------------- | -------- |
| 1. Malicious Traffic | COMPLETE |
| 2. DNS Tunnelling    | COMPLETE |
| 3. Port Scanning     | COMPLETE |
| 4. C2 Communication  | COMPLETE |
| 5. Suspicious HTTP   | PENDING  |

## Day 3 Progress

```text
[✓] Malicious Traffic
[✓] DNS Tunnelling
[✓] Port Scanning
[✓] C2 Communication
[ ] Suspicious HTTP
```

Day 3 is therefore **partially complete**.

I am deliberately leaving Investigation 5 open rather than documenting an investigation that has not yet been properly studied and completed.

---

# SOC Analyst Lessons Learned

This practical work reinforced several important SOC principles:

### 1. Suspicious does not automatically mean malicious

Traffic must be examined in context.

### 2. Baselines matter

Normal traffic provides a comparison point for abnormal behavior.

### 3. Packet fields provide evidence

Important fields include:

* Source IP
* Destination IP
* Source port
* Destination port
* TCP flags
* Sequence numbers
* Acknowledgment numbers
* Payload length
* Application payload
* Timing
* Communication frequency

### 4. Payload inspection is critical

The C2 investigation demonstrated that packet metadata alone was not enough.

The actual payload:

```text
CHECKIN-01
```

provided the strongest evidence that an application-layer check-in had occurred.

### 5. IOCs require investigation

An indicator such as:

```text
User-Agent: sqlmap/1.8
```

should trigger investigation and correlation, not an automatic declaration of compromise.

### 6. Controlled lab traffic can reproduce attacker behavior safely

The investigations demonstrated:

```text
Malicious-looking traffic
DNS tunnelling characteristics
Port scanning
C2-style communication
```

without deploying real malware or connecting to real malicious infrastructure.

# Conclusion

Day 3 moved the investigation process beyond basic protocol identification into practical SOC analysis.

I successfully investigated:

1. Malicious-looking traffic
2. DNS tunnelling characteristics
3. TCP SYN port scanning
4. C2-style communication

The investigations demonstrated how a SOC analyst can move from:

```text
Packet
   ↓
Network behavior
   ↓
Evidence
   ↓
Context
   ↓
Analysis
   ↓
Verdict
```

Investigation 5, **Suspicious HTTP**, remains pending and will be completed after studying the HTTP protocol sufficiently to perform the investigation correctly.

**Day 3 should not be marked fully complete until Investigation 5 is finished.**
