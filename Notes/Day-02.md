# Day 2 - ICMP Packet Analysis with Wireshark



## 1. ICMP Ping Packet Structure



A captured ICMP ping packet can be broken down into:



| Component          |         Size |

| ------------------ | -----------: |

| Ethernet II header |     14 bytes |

| IPv4 header        |     20 bytes |

| ICMP header        |      8 bytes |

| ICMP data          |     56 bytes |

| **Total**          | **98 bytes** |



Calculation:



**14 + 20 + 8 + 56 = 98 bytes**



Since 1 byte = 8 bits:



**98 x 8 = 784 bits**



Therefore, a 98-byte packet contains **784 bits** on the wire.



---



## 2. Ethernet II Header



The Ethernet II header is normally **14 bytes**:



* Destination MAC address - 6 bytes

* Source MAC address - 6 bytes

* EtherType - 2 bytes



**6 + 6 + 2 = 14 bytes**



---



## 3. IPv4 Header



The normal IPv4 header is **20 bytes** when there are no optional IPv4 header fields.



The IPv4 header contains information such as:



* Source IP address

* Destination IP address

* Protocol

* TTL

* Header length

* Total length



---



## 4. ICMP Header



The ICMP Echo Request/Reply header is **8 bytes**:



| Field           |        Size |

| --------------- | ----------: |

| Type            |      1 byte |

| Code            |      1 byte |

| Checksum        |     2 bytes |

| Identifier      |     2 bytes |

| Sequence Number |     2 bytes |

| **Total**       | **8 bytes** |



---



## 5. ICMP Echo Request and Echo Reply



An ICMP ping normally consists of an Echo Request followed by an Echo Reply.



### Echo Request



**ICMP Type = 8**



Example:



**10.0.2.15 -> 8.8.8.8**



### Echo Reply



**ICMP Type = 0**



Example:



**8.8.8.8 -> 10.0.2.15**



The source and destination IP addresses therefore reverse between the request and reply.



---



## 6. Packet Size of Request and Reply



In a normal ICMP exchange where the payload is unchanged, the Echo Reply normally has the same total size as the corresponding Echo Request.



In this capture:



**Echo Request = 98 bytes**



**Echo Reply = 98 bytes**



The same payload is echoed back by the destination.



This is a normal relationship, but packet size is not an absolute rule for every possible ping because payload size and packet options can vary.



---



## 7. ICMP Identifier and Sequence Number



The Identifier and Sequence Number help associate an Echo Reply with its corresponding Echo Request.



Example from the capture:



**Identifier (BE): 12324**



**Sequence Number (BE): 1**



Wireshark identified Frame 2 as the response to **Request frame 1**.



---



## 8. Big Endian and Little Endian



A multi-byte field consists of bytes. The same bytes can be interpreted according to different byte orders.



Example raw bytes:



**00 01**



### Big Endian



The first byte is the most significant byte:



**0x0001 = 1**



### Little Endian



The byte order is reversed for interpretation:



**0x0100 = 256**



Therefore:



**Raw bytes 00 01 -> BE = 1**



**Raw bytes 00 01 -> LE = 256**



BE and LE do not mean that two different values are stored in the packet. They are different interpretations of the same two bytes.



---



## 9. Hexadecimal and Bytes



Every two hexadecimal digits represent one byte.



Example:



**5c 87 95 6a**



This contains:



**4 bytes = 8 hexadecimal digits**



Hexadecimal uses powers of 16.



Example:



**0x0100**



= (0 x 16^3) + (1 x 16^2) + (0 x 16^1) + (0 x 16^0)



= **256**



---



## 10. Captured Echo Reply



The captured Frame 2 contained:



* Packet size: **98 bytes**

* Source: **8.8.8.8**

* Destination: **10.0.2.15**

* ICMP Type: **0 - Echo Reply**

* Code: **0**

* Checksum: **0xf197 - correct**

* Identifier (BE): **12324**

* Sequence Number (BE): **1**

* Response time: **40.939 ms**



This frame was identified by Wireshark as the response to **Request frame 1**.



---



## Key Lessons



1\. A normal Ethernet II header is **14 bytes**.

2\. A normal IPv4 header is **20 bytes** without options.

3\. An ICMP Echo header is **8 bytes**.

4\. A 98-byte ping packet can therefore contain **56 bytes of ICMP data**.

5\. ICMP Type **8 = Echo Request**.

6\. ICMP Type **0 = Echo Reply**.

7\. The source and destination IP addresses reverse between request and reply.

8\. A normal unchanged ICMP payload normally results in the request and reply having the same total size.

9\. Big Endian and Little Endian determine how multi-byte values are interpreted.

10\. **Two hexadecimal digits = one byte.**













# ARP Packet Capture and Analysis

## Objective

I captured and analysed an **ARP Request** and its corresponding **ARP Reply** using Wireshark.

My objective was to understand how ARP resolves an IPv4 address to a MAC address and to identify and interpret the important fields contained within an ARP packet.

---

## 1. Generating ARP Traffic

I generated ARP traffic directly using `arping` rather than using `ping` to trigger ARP.

### Command Used

```bash
sudo arping -c 5 10.0.2.2
```

### Command Breakdown

* `sudo` — runs the command with elevated privileges.
* `arping` — generates ARP traffic directly.
* `-c 5` — sends **5 ARP requests**.
* `10.0.2.2` — the target IPv4 address whose MAC address I wanted to discover.

### Traffic Generated

**ARP REQUEST**

The request essentially asks:

```text
"Who has 10.0.2.2?
 Tell 10.0.2.15."
```

---

# 2. ARP REQUEST — Frame 1

### Ethernet Information

| Field           | Value               |
| --------------- | ------------------- |
| Frame           | `1`                 |
| Size            | `58 bytes on wire`  |
| Size Captured   | `58 bytes`          |
| Interface       | `eth0`              |
| Source MAC      | `08:00:27:5a:87:bc` |
| Destination MAC | `ff:ff:ff:ff:ff:ff` |
| Destination     | Broadcast           |

The ARP Request was sent as an **Ethernet broadcast** because I did not yet know the MAC address associated with `10.0.2.2`.

### ARP Fields

| Field         | Value               | Meaning                                        |
| ------------- | ------------------- | ---------------------------------------------- |
| Hardware Type | Ethernet (`1`)      | Identifies Ethernet as the hardware technology |
| Protocol Type | IPv4 (`0x0800`)     | Identifies IPv4 as the protocol being resolved |
| Hardware Size | `6`                 | Ethernet MAC addresses are 6 bytes             |
| Protocol Size | `4`                 | IPv4 addresses are 4 bytes                     |
| Opcode        | Request (`1`)       | Identifies this packet as an ARP Request       |
| Sender MAC    | `08:00:27:5a:87:bc` | My Kali MAC address                            |
| Sender IP     | `10.0.2.15`         | My Kali IP address                             |
| Target MAC    | `00:00:00:00:00:00` | Unknown at the time of the request             |
| Target IP     | `10.0.2.2`          | The IP address I wanted to resolve             |

### Interpretation

My Kali machine knew its own IP and MAC address, but it did not know the MAC address associated with `10.0.2.2`.

Therefore, it broadcast the ARP Request:

```text
"Who has 10.0.2.2?"
"Tell 10.0.2.15."
```

The target MAC address was set to:

```text
00:00:00:00:00:00
```

because the MAC address had not yet been discovered.

---

# 3. ARP REPLY — Frame 2

The device associated with `10.0.2.2` responded to my ARP Request.

### Ethernet Information

| Field           | Value               |
| --------------- | ------------------- |
| Frame           | `2`                 |
| Size            | `64 bytes on wire`  |
| Size Captured   | `64 bytes`          |
| Interface       | `eth0`              |
| Source MAC      | `52:54:00:12:35:00` |
| Destination MAC | `08:00:27:5a:87:bc` |

Unlike the Request, the Reply was addressed directly to my Kali MAC address.

### ARP Fields

| Field         | Value               | Meaning                                        |
| ------------- | ------------------- | ---------------------------------------------- |
| Hardware Type | Ethernet (`1`)      | Identifies Ethernet as the hardware technology |
| Protocol Type | IPv4 (`0x0800`)     | Identifies IPv4 as the protocol being resolved |
| Hardware Size | `6`                 | MAC address size                               |
| Protocol Size | `4`                 | IPv4 address size                              |
| Opcode        | Reply (`2`)         | Identifies this packet as an ARP Reply         |
| Sender MAC    | `52:54:00:12:35:00` | MAC address belonging to `10.0.2.2`            |
| Sender IP     | `10.0.2.2`          | IP address responding to my request            |
| Target MAC    | `08:00:27:5a:87:bc` | My Kali MAC address                            |
| Target IP     | `10.0.2.15`         | My Kali IP address                             |

### Interpretation

The ARP Reply told my Kali machine:

```text
"10.0.2.2 is at 52:54:00:12:35:00"
```

I could therefore establish the mapping:

```text
IP Address:  10.0.2.2
MAC Address: 52:54:00:12:35:00
```

---

# 4. ARP Request vs ARP Reply

| Feature              | ARP Request             | ARP Reply              |
| -------------------- | ----------------------- | ---------------------- |
| Frame                | `1`                     | `2`                    |
| Opcode               | `1` — Request           | `2` — Reply            |
| Sender IP            | `10.0.2.15`             | `10.0.2.2`             |
| Sender MAC           | `08:00:27:5a:87:bc`     | `52:54:00:12:35:00`    |
| Target IP            | `10.0.2.2`              | `10.0.2.15`            |
| Target MAC           | `00:00:00:00:00:00`     | `08:00:27:5a:87:bc`    |
| Ethernet Destination | Broadcast               | My Kali MAC            |
| Purpose              | Discover the target MAC | Provide the target MAC |

### ARP Exchange

```text
Kali
IP:  10.0.2.15
MAC: 08:00:27:5a:87:bc
        |
        | ARP REQUEST
        | "Who has 10.0.2.2?"
        |
        v
10.0.2.2
MAC: 52:54:00:12:35:00
        |
        | ARP REPLY
        | "10.0.2.2 is at
        |  52:54:00:12:35:00"
        |
        v
Kali
```

---

# 5. Packet Size Observation

Wireshark reported:

* **Frame 1 — ARP Request:** 58 bytes
* **Frame 2 — ARP Reply:** 64 bytes

I initially noticed that the ARP Request contained fewer bytes than the ARP Reply.

The difference does **not** mean that the ARP Reply contains six additional ARP fields. Both packets contain the same fundamental ARP structure.

The observed difference is related to **Ethernet frame sizing, padding, and how the capture interface records the frame**.

Ethernet has a minimum frame-size requirement, so small ARP frames can involve padding at the Ethernet layer.

Therefore, the additional bytes observed in the Reply should not be interpreted as additional ARP information.

---

# 6. What I Learned

I learned that **ARP (Address Resolution Protocol)** is used to resolve an IPv4 address to a MAC address on a local network.

The process I observed was:

```text
ARP REQUEST
"Who has 10.0.2.2?"
        |
        v
ARP REPLY
"10.0.2.2 is at 52:54:00:12:35:00"
```

I learned that an ARP Request is normally broadcast because the sender does not yet know the target's MAC address.

I also learned that the ARP Reply provides the MAC address associated with the requested IP address.

### Key Packet-Analysis Lessons

When analysing ARP traffic in Wireshark, I should pay attention to:

* **Opcode** — identifies whether the packet is a Request or Reply.
* **Sender IP and MAC** — identifies the sender.
* **Target IP and MAC** — identifies the intended target and the address being resolved.
* **Broadcast vs unicast destination** — helps explain how the Request and Reply are delivered.
* **Packet size** — can provide useful clues about the Ethernet frame and capture behaviour.

ARP analysis is also useful during security investigations because abnormal ARP behaviour can be associated with attacks such as **ARP spoofing and ARP poisoning**.







## DNS Packet Capture and Analysis

### Objective

I captured and analyzed DNS traffic using Wireshark to understand how a DNS query travels through the network and how the DNS server responds.

### 1. Generating the DNS Traffic

I started a Wireshark capture on the `eth0` interface and used the following command in Kali:

```bash
nslookup example.com
```

This generated a DNS request asking the DNS server for the IPv4 address associated with `example.com`.

My DNS server was:

```text
192.168.0.1
```

The `nslookup` command returned:

```text
172.66.147.243
104.20.23.154
```

It also returned IPv6 addresses because DNS can provide both IPv4 and IPv6 records.

---

### 2. Ethernet II

The DNS query contained an Ethernet II header:

```text
Source MAC:      08:00:27:5a:87:bc
Destination MAC: 52:54:00:12:35:00
Type:            IPv4 (0x0800)
```

The source MAC address identifies my Kali machine, while the destination MAC identifies the next device on the local network.

Unlike the ARP request I previously captured, the DNS packet was sent to a specific MAC address rather than the broadcast address `ff:ff:ff:ff:ff:ff`.

I learned that DNS does not perform MAC-address resolution itself. DNS resolves domain names and IP addresses, while Ethernet uses MAC addresses for local network delivery. ARP may be used beforehand to discover the MAC address associated with the local next-hop IP when that information is not already known.

---

### 3. IPv4 Header

The IPv4 header contained:

```text
Header Length: 20 bytes (5 × 32-bit words)
Total Length:  57 bytes
TTL:           64
Protocol:      UDP (17)
Source:        10.0.2.15
Destination:   192.168.0.1
```

The IPv4 total length was 57 bytes. Since the IPv4 header was 20 bytes:

```text
57 − 20 = 37 bytes
```

Therefore, the UDP datagram occupied 37 bytes.

The TTL was 64. TTL prevents an IPv4 packet from circulating indefinitely if there is a routing problem. A router normally decreases the TTL by one when forwarding the packet.

The protocol value `17` identifies UDP as the protocol carried inside IPv4.

---

### 4. UDP Header

The UDP header contained:

```text
Source Port:      58894
Destination Port: 53
Length:           37 bytes
Checksum:         0xccee (unverified)
```

The source port `58894` was an ephemeral port selected by my Kali machine.

The destination port was `53`, which is the standard port used by DNS.

The UDP length was 37 bytes. UDP has an 8-byte header, leaving:

```text
37 − 8 = 29 bytes
```

for the DNS payload.

The checksum helps detect corruption in the UDP datagram. Wireshark displayed it as unverified, which does not automatically mean that the packet was corrupted. Virtual machines and network-interface checksum offloading can affect how Wireshark observes checksums.

---

### 5. DNS Query

The DNS query contained:

```text
Transaction ID: 0xc561
Flags:          0x0100
Questions:      1
Name:           example.com
Type:           A
Class:          IN
```

The transaction ID identifies the DNS transaction and allows the client to associate a response with the corresponding query.

The flags `0x0100` indicate a standard DNS query. The QR bit is `0`, meaning that this packet is a query rather than a response.

There was one question.

The requested record type was `A`, meaning that I was asking for an IPv4 address.

The class was `IN`, meaning Internet.

Therefore, the DNS request can be translated into:

> I asked the DNS server: "What IPv4 address is associated with example.com?"

---

### 6. DNS Response

The DNS server returned a standard query response with:

```text
Flags: 0x8180
Result: No error
```

The response contained two A records:

```text
example.com → 172.66.147.243
example.com → 104.20.23.154
```

Both records were:

```text
Type:  A
Class: IN
```

This means the DNS server successfully answered my request and provided two IPv4 addresses associated with `example.com`.

Multiple IPv4 addresses can be returned for the same domain for purposes such as redundancy, availability, traffic distribution, or network optimization.

---

### 7. Transaction ID Matching

I also learned that the DNS response should contain the same Transaction ID as the query it answers.

For my original capture:

```text
Query:    0xc561
Response: 0xc561
```

The Transaction ID does not remain permanently the same. When I restarted Wireshark and generated a new DNS request, a different Transaction ID could be assigned.

The important rule is:

```text
Same transaction:
Query ID = Response ID
```

This allows the DNS client to match the response to the correct request.

---

### 8. Complete DNS Packet Structure

The DNS query I analyzed can be represented as:

```text
Ethernet II
│
├── Source MAC: 08:00:27:5a:87:bc
├── Destination MAC: 52:54:00:12:35:00
└── Type: IPv4
        │
        └── IPv4
            ├── Source: 10.0.2.15
            ├── Destination: 192.168.0.1
            ├── Header: 20 bytes
            ├── Total Length: 57 bytes
            ├── TTL: 64
            └── Protocol: UDP (17)
                    │
                    └── UDP
                        ├── Source Port: 58894
                        ├── Destination Port: 53
                        ├── Length: 37 bytes
                        └── Checksum: 0xccee
                                │
                                └── DNS
                                    ├── Transaction ID: 0xc561
                                    ├── Query: example.com
                                    ├── Type: A
                                    └── Class: IN
```

### What I Learned

I learned that a single DNS communication involves several networking layers, each performing a different function:

```text
MAC      → Local network delivery
IP       → Logical addressing
UDP      → Transport and port identification
DNS      → Domain-name and IP-address resolution
```

I also learned that DNS does not use MAC addresses to perform name resolution. The MAC address belongs to the Ethernet layer and is used for local-hop delivery, while DNS operates at the application layer.

The complete process is therefore:

```text
example.com
     ↓
DNS query
     ↓
DNS server
     ↓
IPv4 addresses
172.66.147.243
104.20.23.154
```

This helped me understand the difference between **DNS resolution, IP addressing, Ethernet addressing, and ARP**, rather than treating them as the same process.





