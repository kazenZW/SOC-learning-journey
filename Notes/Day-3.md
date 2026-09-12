# Day 3 — Practical SOC Network Investigations

## Objective

The objective of Day 3 was to move from individual protocol analysis into practical SOC network investigations. I used controlled lab traffic to observe suspicious and security-relevant network behaviours, capture the traffic in Wireshark, and correlate network events to understand what was happening rather than relying only on protocol definitions.

## Lab Environment

### Systems

* **Kali Linux**

  * Host-only IP: `192.168.56.103`
  * Used for network investigation and traffic generation
* **Metasploitable2**

  * Host-only IP: `192.168.56.101`
  * Used as the controlled vulnerable target

### Tools

* Wireshark
* Nmap
* curl
* dig
* Netcat
* tcpdump

---

# Investigation 1 — Malicious Traffic Analysis

I began with benign traffic to establish a baseline before generating controlled security-relevant traffic.

### Baseline

```bash
ping -c 10 10.0.2.2
```

This produced normal ICMP traffic and provided a comparison point for later observations.

### HTTP User-Agent Testing

I generated normal HTTP traffic and then changed the HTTP User-Agent:

```bash
curl http://example.com
```

```bash
curl -A "Mozilla/5.0" http://example.com
```

```bash
curl -A "sqlmap/1.8" http://example.com
```

The significant observation was:

```text
User-Agent: sqlmap/1.8
```

The `sqlmap/1.8` User-Agent is a security-relevant indicator because SQLmap is a tool used for automated SQL injection testing.

The important SOC distinction is that an indicator does not automatically mean compromise. The traffic demonstrated a suspicious tool identifier in the HTTP request, but it did not by itself prove that an attack succeeded.

---

# Investigation 2 — DNS Tunnelling

I first established normal DNS behaviour and then generated repeated and encoded-looking DNS queries.

### Baseline DNS

```bash
dig example.com
```

### Repeated Subdomain Queries

```bash
for i in {1..20}; do dig "data$i.example.com"; done
```

### Random-Looking Labels

```bash
for i in {1..10}; do dig "$(head -c 12 /dev/urandom | xxd -p).example.com"; done
```

An example of the generated label was:

```text
55fb6c4a67d7ce955b5aa295.example.com
```

The changing, encoded-looking labels demonstrated characteristics that can be associated with DNS tunnelling.

The controlled traffic did not constitute proof of a real DNS tunnel. The exercise was intended to develop the ability to recognize characteristics that would justify further investigation in a real environment.

---

# Investigation 3 — Port Scanning

I used Nmap to generate TCP SYN reconnaissance traffic against the controlled target.

```bash
sudo nmap -sS -p 1-1000 10.0.2.2
```

In Wireshark I examined TCP SYN packets using:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

The capture showed a large number of SYN packets with rapidly changing destination ports.

I then examined SYN/ACK responses:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

The responses showed which probed ports were accepting connections.

This demonstrated how a SOC analyst can identify TCP SYN scanning by looking for a large number of connection attempts across different destination ports within a short period.

---

# Investigation 4 — C2 Communication

I created a controlled TCP communication channel between Kali and Metasploitable2.

### Listener

```bash
nc -lvnp 4444
```

### Controlled Check-In

```bash
echo "CHECKIN-01" | nc -w 2 192.168.56.101 4444
```

I examined the traffic in Wireshark using:

```text
ip.addr == 192.168.56.101 && tcp.port == 4444
```

The traffic showed the TCP three-way handshake followed by a PSH+ACK packet carrying application data.

The payload was 11 bytes:

```text
434845434b494e2d30310a
```

The hexadecimal data decoded to:

```text
CHECKIN-01
```

The final `0A` represented the newline character.

The server acknowledged the data with an ACK. The acknowledgement value of 12 indicated that the 11 bytes sent by the client had been received and that byte 12 was the next expected byte.

There was no server-to-client application payload and no command execution. The exercise therefore demonstrated the network characteristics of a controlled C2-style check-in without creating an actual malicious C2 session.

---

# Investigation 5 — Suspicious HTTP and Live Frame Correlation

I used the Metasploitable2 web server to establish an internal HTTP baseline.

```bash
curl http://192.168.56.101/
```

The returned page exposed directories including:

```text
/twiki/
/phpMyAdmin/
/mutillidae/
/dvwa/
/dav/
```

I then captured the HTTP communication directly with tcpdump:

```bash
sudo tcpdump -i eth1 -n 'tcp port 80 or tcp port 22' -c 10
```

The captured exchange showed:

1. TCP SYN from `192.168.56.103` to `192.168.56.101:80`
2. SYN/ACK response
3. TCP ACK completing the handshake
4. HTTP GET request for `/`
5. TCP ACK from the server
6. HTTP `200 OK` response
7. Client acknowledgement
8. Additional HTTP data
9. Client acknowledgement
10. TCP FIN from the client

The HTTP GET and response could therefore be correlated directly with the underlying TCP session.

This provided a practical baseline for understanding how an analyst can move from a network connection to the application-layer activity occurring inside that connection.

---

# Investigation 6 — Suspicious TLS

I first established normal TLS behaviour:

```bash
curl -v https://example.com
```

The connection successfully negotiated TLS 1.3 and the certificate was verified normally.

I then repeated the connection while disabling certificate verification:

```bash
curl -vk https://example.com
```

The output included:

```text
SSL Trust: peer verification disabled
```

and:

```text
OpenSSL verify result: 14
```

followed by:

```text
SSL certificate verification failed, continuing anyway!
```

The TLS connection itself remained functional and used TLS 1.3.

The important observation was that certificate verification had been deliberately disabled. This is a security-relevant client behaviour, but it does not by itself prove a man-in-the-middle attack.

During packet analysis, Wireshark showed TLS 1.3 handshake/application traffic such as Client Hello, Server Hello, Change Cipher Spec and Application Data. TLS 1.3 encrypts much of the handshake, so the complete certificate exchange was not necessarily visible in the capture without the appropriate session keys.

---

# Investigation 7 — Beaconing

I generated repeated HTTPS connections at controlled intervals:

```bash
for i in {1..6}; do curl -s https://example.com > /dev/null; sleep 5; done
```

I examined the traffic using:

```text
tcp.port == 443
```

The capture contained repeated HTTPS communication with the same destination at approximately five-second intervals.

The repeated sessions generated many TLS packets because each HTTPS connection contains multiple TCP, TLS and application-layer packets.

I observed activity around approximately:

```text
5 seconds
10 seconds
15 seconds
```

The regular timing demonstrated why periodic network communication can be an important SOC indicator.

The individual packets within one HTTPS connection should not be counted as separate beacons. A single connection can contain several packets.

The exercise demonstrated a **beaconing-like pattern**. Periodic traffic alone does not prove malicious command-and-control activity.

---

# Investigation 8 — Network Reconnaissance

I generated controlled reconnaissance traffic against Metasploitable2:

```bash
sudo nmap -sS -p 21,22,23,25,53,80 192.168.56.101
```

I examined the SYN probes using:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.addr == 192.168.56.101
```

The capture showed six consecutive TCP SYN probes.

The packets had:

* The same source IP
* The same destination IP
* Different destination ports
* Consistent packet characteristics
* SYN set
* Consistent sequence behaviour

The repeated probes against different ports demonstrated systematic service discovery against the target.

This investigation moved beyond simply identifying TCP SYN packets and demonstrated how their repetition and variation can reveal reconnaissance behaviour.

---

# Investigation 9 — Traffic Correlation

I then combined several activities into one capture so that the events could be viewed as a sequence rather than as isolated packets.

### Event 1 — Host Reachability

```bash
ping -c 2 192.168.56.101
```

### Event 2 — Service Probing

```bash
sudo nmap -sS -p 22,80 192.168.56.101
```

### Event 3 — HTTP Interaction

```bash
curl http://192.168.56.101/
```

I filtered the capture with:

```text
ip.addr == 192.168.56.101
```

The capture showed:

* ICMP
* TCP
* HTTP
* Browser

The **Browser** protocol label in Wireshark refers to the Microsoft/NetBIOS Computer Browser protocol, not a generic web browser.

The important correlation was the sequence of activity:

```text
ICMP
  ↓
Host reachability
  ↓
TCP SYN probes
  ↓
Service reconnaissance
  ↓
HTTP GET
  ↓
Application interaction
```

The tcpdump capture provided direct evidence of the HTTP connection. The TCP exchange began with the SYN/SYN-ACK/ACK handshake, followed by the HTTP GET request and the server's `HTTP/1.1 200 OK` response.

This demonstrated how a SOC analyst can correlate different protocols and events involving the same host to understand the progression of activity.

The traffic was generated deliberately within the controlled lab environment. The value of the exercise was learning the investigation method: identify individual events, establish their timing and relationship, and then interpret them together as a sequence of behaviour.

---

# Day 3 Summary

Day 3 moved my analysis from individual packet and protocol fields into practical network investigation.

I worked with controlled examples of:

* Malicious or security-relevant traffic indicators
* DNS tunnelling characteristics
* TCP SYN port scanning
* C2-style communication
* Suspicious HTTP indicators
* TLS trust-handling behaviour
* Periodic beaconing-like traffic
* Network reconnaissance
* Multi-event traffic correlation

The main progression was from **observing packets** to **interpreting communication behaviour and relationships between events**.

The final investigation in the SOC roadmap is **PCAP-Based Incident Investigation**, where I will apply these skills to an investigation using a packet capture as the primary evidence source.



















# PCAP-Based Incident Investigation

## Objective

I investigated a previously captured PCAP file to practice identifying relevant network activity, filtering traffic, and separating potentially suspicious behaviour from normal network communication.

The objective was not simply to identify individual packets, but to begin approaching a PCAP as an incident-investigation dataset.

## Investigation File

I worked with:

```text
investigation10.pcap
```

The investigation focused on traffic involving:

```text
192.168.56.103
```

This address belonged to the controlled lab environment.

## Initial PCAP Filtering

I used `tcpdump` to read the capture without generating new traffic:

```bash
sudo tcpdump -nn -r investigation10.pcap 'host 192.168.56.103 and not tcp'
```

### What the command does

* `-nn` prevents hostname and service-name resolution.
* `-r investigation10.pcap` reads an existing PCAP file instead of capturing live traffic.
* `host 192.168.56.103` limits the output to packets involving the selected host.
* `and not tcp` excludes TCP traffic so I can concentrate on non-TCP protocols.

This allowed me to narrow the investigation instead of manually reviewing every packet in the capture.

## Observed ARP Activity

The filtered output included:

```text
09:47:54.578051 ARP, Request who-has 192.168.56.101 tell 192.168.56.103, length 28
```

This showed that:

```text
192.168.56.103
        |
        | ARP Request
        v
"Who has 192.168.56.101?"
```

The host `192.168.56.103` was therefore attempting to resolve the Layer-2 address associated with `192.168.56.101`.

## Investigation Interpretation

I did not treat the ARP request as malicious by itself.

ARP requests are normal network behaviour and can occur when a host needs to communicate with another device on the local network.

The SOC-relevant question is therefore not:

```text
ARP = suspicious
```

but:

```text
Why did this host communicate with this destination?
Was the communication expected?
How frequently did it occur?
What other traffic occurred around the same time?
```

This is an important distinction between packet identification and incident investigation.

## Why Filtering Matters

The investigation demonstrated that a large PCAP can be reduced into smaller investigative views.

For example:

```text
Full PCAP
   |
   +-- Host filter
   |
   +-- Protocol filter
   |
   +-- Time correlation
   |
   +-- Packet inspection
   |
   v
Relevant evidence
```

Filtering is therefore an investigative technique rather than simply a way of making Wireshark or tcpdump easier to read.

## Evidence-Based Analysis

During the investigation I avoided treating a single unusual packet as proof of compromise.

Instead, I considered:

* Source and destination IP addresses
* Protocol
* Ports where applicable
* Packet frequency
* Timing
* Communication direction
* Relationship with other packets
* Whether the activity was expected in the lab environment

This reinforced an important SOC principle:

> A suspicious indicator requires context before it can be classified as malicious.

## Practical Lesson

I learned that PCAP investigation is different from simply learning protocol headers.

Protocol analysis asks:

```text
What does this packet contain?
```

Incident investigation asks:

```text
What does this packet mean in the context of the wider communication?
```

The second question is more important when working as a SOC analyst.

## Investigation Status

This exercise strengthened my ability to:

* Read an existing PCAP with `tcpdump`
* Filter traffic by host
* Exclude a protocol from an investigation
* Identify ARP activity
* Interpret an ARP request
* Distinguish normal network behaviour from evidence requiring further investigation
* Use packet context rather than relying on a single indicator
* Approach PCAP analysis as an incident-investigation workflow

## Conclusion

The PCAP investigation moved my training from individual protocol analysis toward practical incident investigation.

I am now beginning to analyse network captures as collections of related events rather than isolated packets.

The next stage is to continue correlating traffic across protocols, hosts, timestamps and communication patterns to determine whether apparently unusual activity represents normal behaviour, reconnaissance, command-and-control activity, or another form of suspicious network activity.










## 10. Incident Investigation and Log Analysis

### 10.1 Linux Log Analysis

#### 10.1.1 Understanding System Logs

I began the log-analysis phase by learning the purpose of system logs in a SOC investigation.

Logs provide a record of activity occurring on a system. They can contain information about processes, services, sessions, authentication activity, errors, and other system events. From a SOC perspective, logs provide a source of evidence that can be correlated with other telemetry when investigating suspicious activity.

The important distinction I established is that a log entry is evidence of an event or activity; it must still be interpreted in context before determining whether the activity is suspicious.

#### 10.1.2 Linux Log Collection with `journalctl`

I worked with the Linux system journal using `journalctl`. The journal provides access to system and service messages collected by `systemd-journald`.

I used:

```bash
journalctl
```

This allowed me to examine the system journal rather than relying only on individual log files.

I also learned that filtering the journal is important when investigating a specific activity because a complete journal can contain a large amount of unrelated information.

#### 10.1.3 Filtering Linux Logs

I used keyword filtering to narrow the journal to entries related to authentication and sessions:

```bash
sudo journalctl -b | grep -Ei 'sudo|authentication|failed|session'
```

The command searches the current boot's journal and filters the output for terms associated with privilege use, authentication, failures, and sessions.

The purpose was not to assume that every matching entry represented an attack. The purpose was to locate potentially relevant authentication evidence that could then be examined in context.

#### 10.1.4 Authentication-Related Log Evidence

I used the Linux journal to look for evidence of authentication-related failures.

The search did not produce a useful failed-authentication record for the activity being investigated. Therefore, I did not treat the absence of a useful matching entry as proof that no authentication activity occurred.

Instead, this demonstrated an important investigation principle: **the available telemetry determines what can and cannot be established from the evidence.**

At this stage, I had established the basic Linux log-analysis workflow:

**Identify the relevant log source → filter the logs → examine the available evidence → determine whether the evidence answers the investigation question.**

#### 10.1.5 Linux Log Analysis — Session Conclusion

The Linux portion of this session established the foundation for working with system logs and using `journalctl` to locate authentication-related activity.

I did not continue into a full Linux authentication investigation during this session. The deeper authentication investigation is therefore left for the next session rather than being presented as completed work.

**Linux log-analysis status: Completed to the authentication-log investigation boundary.**

---

### 10.2 Windows Authentication Log Investigation

After completing the Linux log-analysis portion, I moved to Windows Security event logs to investigate failed authentication activity.

#### 10.2.1 Event ID 4625 — Failed Logon

I investigated Windows Security Event ID **4625**, which represents a failed logon.

I queried the Security log with:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 | Format-List *
```

The output was too long to analyze efficiently, so I reduced the number of returned events to five:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 | Format-List *
```

This provided a manageable set of failed-logon events for investigation.

#### 10.2.2 First Event Investigated

I focused on the first event:

* **Event ID:** 4625
* **Record ID:** 33881
* **Time:** 12/9/2026 17:21:45
* **Account for which logon failed:** `lenovo`
* **Logon Type:** `2`
* **Caller Process:** `C:\Windows\System32\svchost.exe`
* **Source Network Address:** `127.0.0.1`
* **Source Port:** `0`
* **Keywords:** `Audit Failure`

#### 10.2.3 Determining Whether the Attempt Was Local or Remote

I examined the source address before classifying the event.

The source address was:

```text
127.0.0.1
```

This is the local loopback address. Therefore, the authentication request originated from the same Windows system rather than from a remote network host.

The event also showed:

```text
Logon Type: 2
```

Logon Type 2 represents an **interactive logon**.

Therefore, I classified the event as a **local failed interactive logon attempt**, rather than a remote login attempt.

#### 10.2.4 Identifying the Failed Account and Caller Process

The event identified:

```text
Account Name: lenovo
```

under **Account For Which Logon Failed**.

The event also identified:

```text
Caller Process Name:
C:\Windows\System32\svchost.exe
```

I learned to distinguish these fields rather than treating `lenovo` as the process owner or assuming that `svchost.exe` was itself logging in as `lenovo`.

The event's Subject account was:

```text
KAZEN-ZW$
```

This is separate from the account for which the logon failed.

#### 10.2.5 Determining the Authentication Failure

The event reported:

```text
Failure Reason: Unknown user name or bad password.
Status: 0xC000006D
Sub Status: 0xC000006A
```

The generic failure reason allows for an unknown username or bad password. However, the more specific sub-status:

```text
0xC000006A
```

indicates that the password supplied for the account was incorrect.

Therefore, I concluded that the authentication attempt failed because of an incorrect password.

#### 10.2.6 Repeated Events

The other Event ID 4625 records showed a similar pattern, including:

* `lenovo` as the failed account
* Logon Type 2
* `svchost.exe` as the caller process
* `127.0.0.1` as the source address
* `0xC000006A` as the sub-status

The repetition established a pattern of failed local authentication attempts.

However, I did not treat repetition by itself as proof of malicious activity.

#### 10.2.7 Investigation Boundary

The evidence established that the observed events were local failed interactive authentication attempts for `lenovo`, associated with `svchost.exe`, originating from `127.0.0.1`, with the specific failure indicating an incorrect password.

The remaining investigation question was **why `svchost.exe` was generating the authentication request and which service or activity was responsible**.

I did not assume that `svchost.exe` was malicious simply because it appeared in the event. Further correlation would be required to identify the specific service responsible.

---

### 10.3 Investigation Skills Established

Through this investigation, I practiced moving from raw log data to an evidence-based conclusion.

I learned to:

* Identify an appropriate log source for an investigation.
* Use `journalctl` to examine Linux system logs.
* Filter logs for relevant authentication-related activity.
* Recognize when available telemetry is insufficient to answer an investigation question.
* Query Windows Security logs for Event ID 4625.
* Reduce excessive event output to a manageable set for analysis.
* Distinguish a local loopback address from a remote source.
* Interpret Windows Logon Type 2.
* Distinguish the failed account from the Subject account.
* Identify the caller process.
* Use status and sub-status values to determine the specific authentication failure.
* Recognize repeated events as a pattern without automatically classifying them as malicious.
* Separate established facts from questions requiring further investigation.














