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






