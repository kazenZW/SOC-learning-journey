# Day 3 â€” Practical SOC Network Investigations

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

# Investigation 1 â€” Malicious Traffic Analysis

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

# Investigation 2 â€” DNS Tunnelling

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

# Investigation 3 â€” Port Scanning

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

# Investigation 4 â€” C2 Communication

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

# Investigation 5 â€” Suspicious HTTP and Live Frame Correlation

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

# Investigation 6 â€” Suspicious TLS

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

# Investigation 7 â€” Beaconing

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

# Investigation 8 â€” Network Reconnaissance

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

# Investigation 9 â€” Traffic Correlation

I then combined several activities into one capture so that the events could be viewed as a sequence rather than as isolated packets.

### Event 1 â€” Host Reachability

```bash
ping -c 2 192.168.56.101
```

### Event 2 â€” Service Probing

```bash
sudo nmap -sS -p 22,80 192.168.56.101
```

### Event 3 â€” HTTP Interaction

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
  â†“
Host reachability
  â†“
TCP SYN probes
  â†“
Service reconnaissance
  â†“
HTTP GET
  â†“
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

The search did not initially produce a useful failed-authentication record for the activity being investigated. Therefore, I did not treat the absence of a useful matching entry as proof that no authentication activity occurred.

Instead, this demonstrated an important investigation principle: **the available telemetry determines what can and cannot be established from the evidence.**

At this stage, I had established the basic Linux log-analysis workflow:

**Identify the relevant log source â†’ filter the logs â†’ examine the available evidence â†’ determine whether the evidence answers the investigation question.**

#### 10.1.5 Linux Log Analysis â€” Session Conclusion

The Linux portion of the initial log-analysis work established the foundation for working with system logs and using `journalctl` to locate authentication-related activity.

I then continued the investigation specifically into Linux authentication events before moving to Windows.

#### 10.1.6 Linux Authentication Log Analysis

I continued my SOC log-analysis training by examining Linux authentication events. The objective was to identify authentication failures, successful authentication, session creation, and whether the activity was local or remote.

##### Searching Authentication Events

I searched the current boot journal for authentication-related activity:

```bash
sudo journalctl -b | grep -Ei 'sudo|authentication|failed|session'
```

Initially, there was no recorded failed authentication event in the output.

I then generated a `sudo` authentication event and searched the journal again:

```bash
sudo journalctl -b | grep -Ei 'sudo|authentication|session' | tail -20
```

The important event was:

```text
pam_unix(sudo:auth): authentication failure;
logname=kali uid=1000 euid=0 tty=/dev/pts/0
ruser=kali rhost= user=kali
```

##### Interpreting the Authentication Failure

I identified this as a **local sudo authentication failure** involving the `kali` user.

The important fields were:

* `user=kali` â€” the account involved
* `ruser=kali` â€” the requesting user
* `tty=/dev/pts/0` â€” the terminal involved
* `rhost=` â€” empty, meaning no remote host was recorded
* `pam_unix(sudo:auth)` â€” the authentication was handled through PAM for `sudo`

I did not classify this as a remote attack because the event contained no remote host.

I also did not assume why authentication failed because the log did not provide enough evidence to determine the exact reason.

##### Successful sudo Authentication

I then observed a successful sudo session:

```text
pam_unix(sudo:session): session opened for user root(uid=0) by kali(uid=1000)
```

The corresponding session later closed:

```text
pam_unix(sudo:session): session closed for user root
```

This showed that the `kali` user successfully authenticated through `sudo` and obtained a root session.

##### SOC Assessment

My assessment was:

**Local authentication activity â€” no evidence of a confirmed attack.**

The failed authentication was associated with the local `kali` account and did not contain a remote source address. A successful sudo session followed.

The important SOC lesson was that an authentication failure is an **event requiring context**, not automatically an incident.

I learned to distinguish:

```text
Authentication failure
        â†“
Security-relevant event
        â†“
Investigate context
        â†“
Do not automatically classify as an attack
```

I also learned that PAM records authentication and session activity for Linux services such as `sudo`.

### Linux Authentication Status

**Completed.**

---

### 10.2 Windows Authentication Log Investigation

After completing the Linux authentication investigation, I moved to Windows Security event logs to investigate failed authentication activity.

#### 10.2.1 Event ID 4625 â€” Failed Logon

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
* Investigate Linux authentication failures and successful sessions.
* Distinguish local authentication activity from remote authentication activity.
* Understand the role of PAM in Linux authentication and session logging.
* Query Windows Security logs for Event ID 4625.
* Reduce excessive event output to a manageable set for analysis.
* Distinguish a local loopback address from a remote source.
* Interpret Windows Logon Type 2.
* Distinguish the failed account from the Subject account.
* Identify the caller process.
* Use status and sub-status values to determine the specific authentication failure.
* Recognize repeated events as a pattern without automatically classifying them as malicious.
* Separate established facts from questions requiring further investigation.


# Windows Log Analysis â€” Final Practical Assessment

## Practical Windows Authentication Investigation

I completed a practical investigation using Windows Security Event Log evidence to determine what happened, distinguish normal system activity from potentially suspicious activity, and identify what additional evidence would be required.

### 1. Event ID 4625 â€” Failed Logon

The 4625 event showed a failed authentication attempt involving the `lenovo` account.

Evidence:

* Event ID: `4625`
* Logon Type: `2` â€” Interactive
* Account for which logon failed: `lenovo`
* Failure reason: `Unknown user name or bad password`
* SubStatus: `0xC000006A`
* Caller process: `C:\Windows\System32\svchost.exe`
* Source Network Address: `127.0.0.1`
* Workstation: `KAZEN-ZW`

The source address was the local loopback address, so the evidence did not indicate a remote authentication source. The failure was consistent with a bad password.

I did not classify the event as malicious because the available evidence did not establish malicious intent or compromise.

### 2. Event ID 4624 â€” Successful Logon

The 4624 event showed a successful authentication in a service/system context.

Important evidence included:

* Account: `SYSTEM`
* Logon Type: `5` â€” Service
* Process: `services.exe`
* Source network address: blank

This was not evidence of a user remotely logging into the machine. The Logon Type and process context were consistent with Windows service activity.

### 3. Event ID 4688 â€” Process Creation

The 4688 event showed:

* New process: `services.exe`
* Creator process: `wininit.exe`

I interpreted this as normal Windows operating-system activity. `wininit.exe` creating `services.exe` is consistent with Windows startup and service initialization.

There was no evidence in this event alone indicating malicious process creation.

### 4. Event ID 4740 â€” Account Lockout

I searched for Event ID `4740` and did not find a matching account-lockout event.

The absence of 4740 does **not** mean that no failed authentication occurred, because a 4625 event was observed. It means that no account-lockout event was recorded in the evidence examined.

Therefore, I found no evidence that the failed authentication resulted in an account lockout.

### 5. Correlation and Timeline

I compared the authentication and process events rather than treating each event independently.

The 4625 event represented a local interactive authentication failure.

The later 4624 event represented a successful service logon involving `SYSTEM`, followed by a 4688 process-creation event showing `wininit.exe` creating `services.exe`.

Although the events occurred relatively close together in time, their different logon types, accounts, and process contexts did not provide enough evidence to establish that they were part of the same authentication sequence.

### 6. Final Investigation Conclusion

Based on the available evidence, I classified the activity as **benign/expected system activity with one observed local authentication failure**.

I found:

* A local failed interactive authentication attempt.
* No evidence of a remote authentication source.
* A successful service/system logon.
* Normal `wininit.exe â†’ services.exe` process creation.
* No observed account-lockout event.
* No evidence sufficient to establish malicious activity.

I therefore did **not** escalate the activity as a confirmed security incident.

### Student Assessment Result

**PASS**

I demonstrated the ability to:

* Interpret Windows authentication events.
* Distinguish Logon Types.
* Identify local versus remote authentication evidence.
* Interpret failed and successful authentication.
* Investigate account-lockout evidence.
* Interpret process-creation events.
* Correlate multiple Windows Security events.
* Separate observed evidence from assumptions.
* Avoid declaring an incident without sufficient evidence.

## Windows Log Analysis â€” Module Status

**COMPLETE**

The Windows Log Analysis objectives are now satisfied.

### Next SOC Module

**SIEM**

Planned progression:

1. SIEM fundamentals
2. Search and filtering
3. Event searching
4. Field-based investigation
5. Correlation
6. Alert generation
7. Alert investigation
8. Practical SIEM investigation






# SIEM Theory â€” Basic Understanding

## What is a SIEM?

A **SIEM (Security Information and Event Management)** is a system used to **collect, centralize, search and analyze security-related logs and events** from different systems.

Instead of checking every machine separately, a SIEM provides a central place where an analyst can examine activity.

## Why is a SIEM used?

Systems generate large amounts of logs. A SIEM helps an analyst:

* Bring logs from different systems into one place.
* Search through large amounts of events.
* Filter events to find relevant activity.
* Examine events using their fields and timestamps.
* Identify relationships and patterns between events.

## Logs and Events

A **log** is a record produced by a system, service or application.

An **event** is an individual recorded occurrence within that data.

Events can contain information such as:

* Time
* Host
* User
* Source
* Event type
* Source IP address
* Action or result

Understanding these fields allows an analyst to investigate activity more effectively.

## Centralization

The main idea behind a SIEM is centralization.

For example:

```text
Windows ---------â”
Linux -----------â”¤
Servers ---------â”¼--> SIEM
Applications ----â”¤
Network ---------â”˜
```

The SIEM receives information from different sources and makes it available for centralized analysis.

## Searching and Filtering

Because a SIEM may contain thousands of events, an analyst normally starts by narrowing the data.

For example, an analyst may search for:

* A particular host
* A username
* Failed logins
* A specific event type
* A particular time period

Filtering does not automatically mean that something is malicious. It simply helps isolate information that needs to be examined.

## Basic SIEM Analysis

The basic analytical process we learned is:

```text
Collect -> Search -> Filter -> Examine -> Correlate -> Investigate
```

The important idea is that **one event may not mean much by itself**. Looking at related events can provide the context needed to understand what actually happened.

## Core Understanding

A SIEM is therefore more than a place to store logs.

It provides a **centralized environment where security events can be searched and analyzed to understand activity across systems.**












# Windows Log Analysis â€” Splunk Progress

## Current Stage

**Windows Security Log Analysis â†’ Process Creation â†’ Persistence Investigation**

My objective is to investigate Windows activity in Splunk using evidence and event correlation rather than treating individual events as proof of compromise.

---

# PART I â€” CONFIRMED FINDINGS

## 1. Windows Security Log Collection

I confirmed that Windows Security logs were previously being successfully ingested into Splunk.

My main search was:

```spl id="x1w2m3"
index=main sourcetype="WinEventLog:Security"
```

Earlier searches returned thousands of Security events.

Event IDs I confirmed as present included:

* **4624** â€” successful logon
* **4625** â€” failed logon
* **4672** â€” special privileges assigned
* **4688** â€” process creation
* **4696** â€” primary token assigned to process
* **4826** â€” Boot Configuration Data loaded

---

## 2. Event 4688 â€” Process Creation

I investigated Event 4688 using:

```spl id="a4b5c6"
index=main sourcetype="WinEventLog:Security" EventCode=4688
| table _time Account_Name New_Process_Name Creator_Process_Name Process_Command_Line
| sort _time
```

I found approximately **45 Event 4688 records**.

Observed processes included:

```text
smss.exe
csrss.exe
wininit.exe
services.exe
winlogon.exe
lsass.exe
Registry
```

### Confirmed field meanings

`New_Process_Name` identifies the newly created process.

`Creator_Process_Name` identifies the recorded creator/parent process.

`Creator_Process_ID` and `New_Process_ID` allow process relationships to be correlated.

A blank or `-` value does not automatically mean that something did not happen.

For example:

```text
Process Command Line:
```

being empty means the command line was **not recorded in that event**.

It does not prove that the process had no command line.

---

## 3. EventType Clarification

I established that **EventType, EventCode, and Type are separate fields**.

For Windows Security events:

```text
EventType=0 â†’ Success Audit
EventType=1 â†’ Failure Audit
```

For the 4688 events I examined:

```text
EventType=0
Keywords=Audit Success
Type=Information
TaskCategory=Process Creation
```

Therefore, `EventType=0` does not mean "Information."

`Type=Information` is a separate field.

I also established that System/Application EventType values must not automatically be interpreted using the Security-log EventType scheme.

---

## 4. LSASS Event

I examined a specific 4688 event:

```text
New Process Name:
C:\Windows\System32\lsass.exe

Creator Process Name:
C:\Windows\System32\wininit.exe

New Process ID:
0x498

Creator Process ID:
0x408
```

The raw event contained:

```text
Process Command Line:
```

with no value.

### Confirmed conclusion

> LSASS was created by wininit.exe, but the command line was not recorded in this event.

I did not conclude that LSASS had no command line.

---

## 5. Boot/Reboot Correlation

I correlated Windows Security and System events around:

**2026-09-24 13:23â€“13:26**

I confirmed a System Event 41:

```text
EventCode=41
EventType=1
SourceName=Microsoft-Windows-Kernel-Power
Type=Critical
```

Message:

> The system has rebooted without cleanly shutting down first.

Other events occurring during the startup sequence included:

* NTFS initialization
* FilterManager startup
* UMDF startup
* Kernel-PnP activity
* Security Event 4826
* Security Event 4696
* Security Event 4688
* Windows startup processes

Event 4826 showed that Boot Configuration Data had been loaded.

The observed settings included:

```text
Test Signing: No
Kernel Debugging: No
Flight Signing: No
Disable Integrity Checks: No
```

### Confirmed interpretation

These observations establish that the 4688 process-creation events occurred in the context of Windows startup following an unclean reboot.

They do **not** establish that the system is clean.

---

## 6. Registry Process Correlation

I observed Event 4696 and Event 4688 associated with:

```text
PID = 0xac
Process = Registry
```

Event 4696 indicated that a primary token was assigned to the process.

Event 4688 indicated that the process was created.

Because both events referenced PID `0xac`, I can correlate them directly.

### Confirmed limitation

Seeing a process named `Registry` is **not by itself evidence of registry persistence**.

No registry-persistence conclusion has been made from that event alone.

---

## 7. Windows Service Persistence Check

I investigated service-installation events:

```text
EventCode 4697
EventCode 7045
```

I first searched around the reboot and received no results.

I then searched the available dataset:

```spl id="d7e8f9"
index=main (EventCode=4697 OR EventCode=7045)
| stats count by sourcetype EventCode
```

Result:

**No results.**

### Confirmed finding

Event IDs 4697 and 7045 are not currently available in the searchable dataset.

Therefore, I cannot use those events to investigate service installation from the current data.

This does **not** prove:

* that no services exist
* that no service was installed
* that service persistence did not occur

It only establishes that these specific event records are not currently available to my search.

---

## 8. Current Splunk Data Problem

After the service investigation, my previously working Security search returned no results:

```spl id="g0h1i2"
index=main sourcetype="WinEventLog:Security"
```

I tested:

```spl id="j3k4l5"
index=main
| stats count
```

It returned:

**1 event**

I inspected that event and confirmed:

```text
host = KAZEN-ZW
source = WinEventLog:System
sourcetype = WinEventLog:System
EventCode = 41
```

Timestamp:

```text
2026-09-24 13:23:42.395 +02:00
```

The event was the previously identified Kernel-Power Event 41.

### Confirmed current state

At the point the investigation was paused, searches against `main` were returning only this one System event instead of the thousands of Security events that had previously been searchable.

I therefore stopped the persistence investigation rather than continuing with incomplete data.

---

# PART II â€” PLANNED NEXT STEPS

## 1. Verify the Full `main` Index

Run:

```spl id="m6n7o8"
index=main earliest=0 latest=now
| stats count
```

### Purpose

Determine whether `main` genuinely contains only one searchable event across the full available time range.

---

## 2. If `main` Still Contains Only One Event

Investigate the Splunk data path.

Specifically determine whether:

* Windows Security events are still being forwarded.
* Windows events are being sent to another index.
* The Windows sourcetype changed.
* The Windows input/forwarder stopped.
* Splunk ingestion changed after a restart.
* The Security data is unavailable to the current search for another reason.

I will diagnose the cause before changing configuration.

---

## 3. Resume Persistence Investigation

Once Windows Security data is confirmed to be searchable again, continue investigating persistence mechanisms.

Potential mechanisms to investigate include:

* Registry Run/RunOnce locations
* Services
* Scheduled Tasks
* Winlogon-related persistence
* Startup folders
* Other Windows persistence mechanisms supported by the available telemetry

The specific mechanism should be chosen based on the evidence actually available in Splunk.

---

## 4. Continue Correlation

For suspicious activity, correlate:

* Timestamp
* Event ID
* Process ID
* Parent Process ID
* Account
* Logon ID
* Process path
* Command line
* Registry activity
* Service activity
* Scheduled-task activity
* Authentication events
* System events
* Network activity where available

The goal is to build an evidence-based timeline rather than classify an individual event in isolation.

---

# INVESTIGATION METHOD

For each finding, I use:

1. **What happened?**
2. **What does the field literally say?**
3. **What can I infer?**
4. **What can I NOT infer?**
5. **What is the legitimate explanation?**
6. **What malicious explanation is possible?**
7. **What additional evidence would distinguish the possibilities?**
8. **Correlate before concluding.**

I do not classify an event as malicious or benign based on a single indicator.

My objective is to build an evidence-based Windows investigation in Splunk and eventually correlate Windows, Linux, authentication, process, persistence, and network evidence.










# SIEM Investigation â€” Kernel-Power and Windows Logon Correlation

## Investigation Objective

Todayâ€™s investigation focused on host-based forensic analysis of the Windows endpoint `KAZEN-ZW` using Splunk, Windows Event Logs, PowerShell, temporal correlation, and cross-source analysis.

The investigation followed the methodology:

**Incident â†’ Timeline â†’ Correlation â†’ Hypothesis â†’ Test â†’ Conclusion**

The main objective was to determine what could be established from the available evidence without treating correlation as proof of causation.

---

## Phase 1 â€” Kernel-Power Investigation

### Event Investigated

**Event ID:** 41
**Source:** `Microsoft-Windows-Kernel-Power`
**Time:** `2026-09-24 13:23:42.395`
**Task Category:** 63
**BugcheckCode:** `0`

The BugcheckCode was extracted from the System log using PowerShell.

The value `0` indicates that Windows did not record a bugcheck code for the event. This does **not**, by itself, establish whether the underlying cause was physical power loss, thermal protection, hardware failure, or another type of abrupt shutdown.

### Correlation Findings

Additional System and Application logs were examined around the event.

WHEA-Logger results did not provide supporting hardware-error events in the queried channel.

The investigation also identified later Splunk-related `.rbsentinel` events, but their timestamps occurred on September 26â€“27 and therefore could not be used as direct evidence for the September 24 Kernel-Power event.

### Final Finding

The September 24 Event 41 was ultimately explained by the known physical action taken on the machine: the system had become extremely slow/unresponsive and the power button was used to force the shutdown.

Therefore, the investigation did **not** establish thermal shutdown as the cause.

---

# Phase 2 â€” Splunk `.rbsentinel` Artifact Correlation

Splunk `_internal` logs were searched for bucket and repair-related warnings.

The investigation found repeated messages from `IndexerService` involving the removal of `.rbsentinel` artifact directories.

These events occurred primarily on:

* September 26
* September 27

The `.rbsentinel` artifacts were treated as **Splunk bucket/recovery artifacts**, not as Kernel-Power events.

### Investigative Purpose

The objective was not to determine who removed the artifacts.

Instead, the investigation considered whether recurring artifact appearance/removal could be correlated chronologically with:

**Kernel-Power â†’ system restart/boot â†’ Splunk recovery state â†’ sentinel removal**

Repeated sequences could potentially establish a recurring temporal relationship.

However, the available September 26â€“27 sentinel events could not be used to prove what happened during the September 14 Kernel-Power sequence.

### Finding

The artifacts are useful forensic timeline markers, but `.rbsentinel` removal alone does not establish that a Kernel-Power event caused them.

---

# Phase 3 â€” Splunkd Service Logon

## Event

**Event ID:** 4624
**Time:** `2026-09-14 21:31:38.242`
**Account:** `NT SERVICE\Splunkd`
**Logon Type:** `5`
**Process:** `C:\Windows\System32\services.exe`

The event showed:

* Subject: `KAZEN-ZW$`
* Security ID: `S-1-5-18`
* Logon Type: `5`
* New Logon: `Splunkd`
* Domain: `NT SERVICE`
* Process: `services.exe`
* Authentication: `Negotiate`
* Logon Process: `Advapi`
* No network source address

### Interpretation

Logon Type 5 represents a **service logon**.

The event demonstrates that Windows created a service logon session for `NT SERVICE\Splunkd`.

`services.exe` is the Windows Service Control Manager process responsible for managing Windows services.

However, the event alone does not prove:

* that Splunk indexing began at exactly that millisecond;
* that `services.exe` launched Splunkd at exactly that moment; or
* that the event itself was responsible for a preceding system restart.

### Finding

The evidence supports a normal Windows service-logon event for Splunkd, but its exact relationship to the earlier system state was not established from this event alone.

---

# Phase 4 â€” Windows Interactive Logon Investigation

## Investigation Target

**Event ID:** 4624
**Time:** `2026-09-15 09:40:49.112`
**Account:** `lenovo`
**Logon Type:** `2`

The event contained:

* Account: `KAZEN-ZW\lenovo`
* Logon Type: `2` â€” Interactive
* Process ID: `0xc50`
* Process: `C:\Windows\System32\svchost.exe`
* Workstation: `KAZEN-ZW`
* Source Address: `127.0.0.1`
* Source Port: `0`
* Logon Process: `User32`
* Authentication Package: `Negotiate`
* Elevated Token: `Yes` on one corresponding 4624 event
* Linked Logon ID: `0x6FC02B`
* Logon ID: `0x6FBFA4`

The investigation found another 4624 event at the **same timestamp** with the same process ID and linked logon identifiers but a different elevation state.

---

## Correlation of the Logon Events

The surrounding five-minute timeline was examined.

Important events included:

| Time          |     Event | Observation                         |
| ------------- | --------: | ----------------------------------- |
| 09:40:44.167  |      4672 | SYSTEM special privileges           |
| 09:40:44.167  |      4624 | SYSTEM Type 5 / `services.exe`      |
| 09:40:47.777  |      5379 | Credential-related event            |
| 09:40:48.484  |      4798 | `KAZEN-ZW$` â†’ `lenovo`, `lsass.exe` |
| 09:40:49.112  |      4672 | `lenovo` privileges                 |
| 09:40:49.112  |      4624 | `lenovo`, Type 2                    |
| 09:40:49.112  |      4624 | `lenovo`, Type 2, elevated token    |
| 09:40:49.112  |      4648 | Explicit credentials, `svchost.exe` |
| 09:40:58.804  |      4799 | `KAZEN-ZW$`, `svchost.exe`          |
| 09:40:58.978+ | 4624/4672 | Additional SYSTEM service activity  |

The two 4624 events shared the same:

* timestamp;
* process ID `0xc50`;
* account;
* linked logon relationship.

One recorded `Elevated Token = No`, while the other recorded `Elevated Token = Yes`.

---

# Phase 5 â€” Event 4648 Correlation

The associated Event 4648 showed:

* Account whose credentials were used: `lenovo`
* Target server: `localhost`
* Process ID: `0xc50`
* Process: `C:\Windows\System32\svchost.exe`
* Network address: `127.0.0.1`
* Port: `0`

Event 4648 represents an attempted logon using **explicit credentials**.

The identical timestamp and process ID strongly correlate this event with the 4624 logon events.

The loopback address `127.0.0.1` supports the conclusion that the authentication activity was local rather than originating from a conventional remote network source.

The evidence does not, however, identify exactly which user-facing action initiated the request.

---

# Phase 6 â€” Testing the Precursor Hypotheses

The investigation tested whether the 09:40:49 interactive logon was preceded by a system sleep/resume or startup event.

### Sleep/Resume Search

The following System Event IDs were checked:

* Event 1 â€” Power-Troubleshooter
* Event 42 â€” Kernel-Power
* Event 107 â€” Kernel-Power

No matching results were returned for September 15.

### Startup/Shutdown Search

The following events were also checked:

* Event 6005
* Event 6006
* Event 12
* Event 13

No matching results were returned for September 15.

### Important Forensic Limitation

The absence of these specific events does **not** prove that the computer was definitely powered off, definitely awake, or that a particular physical action occurred.

It only establishes that the queried event IDs did not provide evidence for those states in the available logs.

Therefore, the investigation did not claim that a cold boot, screen unlock, or UAC prompt was definitively responsible.

---

# Final Finding for the 09:40:49 Event

The available evidence establishes that:

1. `KAZEN-ZW\lenovo` received an interactive Type 2 logon session.
2. The activity was local, with source address `127.0.0.1`.
3. `svchost.exe` with PID `0xc50` was associated with the authentication activity.
4. Event 4648 shows explicit use of the `lenovo` credentials against `localhost`.
5. The 4624 events share the same timestamp, process ID, and linked logon identifiers.
6. One corresponding logon session had an elevated token while another did not.
7. The queried System logs did not establish a preceding sleep/resume or startup event.
8. The available evidence is **consistent with local authentication/token activity**, potentially including elevation-related Windows behavior, but it does not independently prove the exact user action or application that triggered it.

The exact application or user action responsible would require further correlation, such as relevant Event ID 4688 process-creation events or additional Windows operational logs.

---

# SOC Methodology Learned

This investigation reinforced several important forensic principles.

### 1. Start with an Anchor Event

A known event provides a fixed point from which the investigation can expand.

### 2. Build a Timeline

Events immediately before and after the anchor can reveal sequences that are invisible when looking at a single event.

### 3. Correlate Across Sources

Security, System, Application, and Splunk internal logs provide different perspectives of the same host.

### 4. Correlation Is Not Causation

Events occurring together can demonstrate a relationship or sequence without proving that one caused the other.

### 5. Absence of Evidence Must Be Interpreted Carefully

A missing event can eliminate a hypothesis only when the logging conditions are understood. A blank search is not automatically proof that the underlying action never occurred.

### 6. Test the Hypothesis

Instead of accepting the first explanation, search for evidence that supports **and contradicts** the hypothesis.

### 7. Identify Evidence Gaps

A good investigation ends by distinguishing:

**What was proven â†’ what was strongly supported â†’ what remains unknown.**

---

# Overall Investigation Outcome

The investigation progressed from isolated Windows events to a structured host-based forensic methodology.

The most important learning was not a single Event ID. It was the process of moving from:

**Event -> Context -> Timeline -> Correlation -> Hypothesis -> Verification -> Evidence Gap**

This approach will be reused for future SIEM investigations.

