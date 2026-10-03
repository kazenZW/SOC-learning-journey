# Day 04 — Splunk Evidence Validation, Index Verification and Windows Code Integrity Investigation

## 1. Continuation from Day 03

After completing the authentication and process investigation documented in Day 03, I continued investigating the Windows evidence in Splunk.

The purpose of this stage was not simply to find another event and label it suspicious. I wanted to verify that the data I was searching was actually present, understand the structure of the index, establish which Windows event types were available, and only then interpret individual events.

This became important because some searches appeared to return little or no information. Instead of assuming that the event had not occurred, I treated the search result itself as something that needed to be verified.

---

# Part A — Splunk Evidence and Index Validation

## 2. Verifying the Splunk Event Before Interpreting It

I continued validating Windows Security events associated with the earlier investigation.

The investigation involved activity associated with the `lenovo` account and Windows process creation events. I examined Event ID 4688 and related records to determine what the events actually established.

One important point I confirmed was the meaning of the Windows audit field:

* `EventType=0` represents **Audit Success**.
* A blank **Process Command Line** does not prove that no command line existed. It means that a command line was not recorded in that event.

This distinction was important because I did not want to turn missing fields into conclusions.

I also examined process relationships such as the creation of `lsass.exe` by `wininit.exe`. The parent-child relationship itself needed to be interpreted in Windows context rather than automatically treated as suspicious.

My approach remained:

**Event → Context → Timeline → Correlation → Hypothesis → Verification → Evidence Gap**

The main lesson at this stage was that an event must be interpreted according to what it actually records.

---

## 3. Investigating the Apparent Missing-Event Problem

During the investigation, some searches appeared to show that expected Windows events were missing.

Initially, this could have been interpreted as:

> “The event did not happen.”

I did not accept that conclusion without checking the underlying Splunk data.

I therefore changed the question from:

> “Why can't I find this event?”

to:

> “Is the event actually absent from the data, or am I failing to search the data correctly?”

This distinction became one of the most important lessons from the investigation.

---

## 4. Verifying the Index

I checked the Splunk index and its available event data rather than relying on the result of one search.

The `main` index contained approximately **91,000 events**.

The major sourcetypes/data categories I observed included:

| Sourcetype / Data      | Events |
| ---------------------- | -----: |
| `WinEventLog:Security` | 59,357 |
| CPU Load               |  9,332 |
| Network Interface      |  8,685 |
| Memory                 |  4,668 |
| System                 |  3,474 |
| Setup                  |  3,070 |
| Application            |  2,224 |
| `auth`                 |    433 |

This changed the interpretation of the earlier search problem.

The data was not simply absent from Splunk. There was a substantial amount of Windows Security data available.

The investigation therefore had to move from **data existence** to **search visibility and event coverage**.

---

## 5. Why Index Verification Matters

I learned that a failed search can have several different explanations:

1. The event genuinely did not occur.
2. The event occurred outside the selected time range.
3. The event exists under a different sourcetype.
4. The event is stored in another index.
5. The EventCode is not being searched correctly.
6. The field being searched does not contain the expected value.
7. The data exists but the query is too restrictive.
8. The event may not have been collected by the forwarder at all.

Therefore:

> **No search result is not automatically evidence that the underlying event did not happen.**

This became a major part of my SOC methodology because SIEM investigation depends not only on interpreting events, but also on verifying the reliability and completeness of the data being searched.

---

## 6. Checking Windows Security Event Coverage

After establishing that the `main` index contained a large amount of Security data, I continued examining which Windows Security EventCodes were actually available.

I specifically considered events relevant to process execution, credentials, and persistence, including:

* **4688** — process creation
* **4696** — primary token assigned to process
* **4697** — service installed in the system
* **7045** — service installation recorded by Service Control Manager

The important distinction was between:

> “I did not find the event in this search”

and

> “The event does not exist in the collected dataset.”

I therefore treated event coverage and query correctness as part of the investigation itself.

---

## 7. Searching the Windows Security Data

I used Splunk searches to inspect the available Windows Security events rather than relying only on individual event messages.

The investigation involved narrowing searches by index, sourcetype, EventCode, host, account and time.

For example, the basic structure was:

```spl
index=main sourcetype="WinEventLog:Security"
```

I then narrowed the investigation according to the specific event being examined.

For Event 4688, the investigation could be constrained with:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
```

For multiple relevant event types:

```spl
index=main sourcetype="WinEventLog:Security" EventCode IN (4688,4696,4697)
```

The important lesson was not the individual SPL command. It was the process of progressively narrowing the search while verifying that the underlying data existed.

---

## 8. Establishing the Evidence Boundary

At the end of this part of the investigation, I had established that:

* Splunk contained a substantial Windows Security dataset.
* The `main` index contained approximately 91,000 events.
* `WinEventLog:Security` represented the largest observed event category.
* Event 4688 was available for process-creation investigation.
* Event interpretation required attention to individual fields rather than assumptions.
* A missing result from one query could not automatically be treated as proof that an event never occurred.

This became a separate lesson from the original Day 03 investigation.

Day 03 focused on **investigating the activity represented by an event**.

Day 04 added another layer:

> **Before trusting the absence of evidence, verify the evidence source and search path.**

---

# Part B — Windows Bonjour and Code Integrity Investigation

## 9. Moving From Splunk to Windows Event Evidence

After the Splunk validation work, I continued investigating Windows security warnings involving `mdnsNSP.dll`, Bonjour and Local Security Authority-related activity.

I did not assume that the warning represented malware.

Instead, I wanted to establish:

1. What the DLL actually was.
2. Where it came from.
3. Whether it was digitally signed.
4. When Bonjour was installed.
5. What service was installed.
6. Which processes later attempted to load the DLL.
7. Why Windows Code Integrity blocked those loads.
8. What remained unknown.

---

## 10. Establishing the DLL Identity

I first examined the file itself:

```powershell
Get-Item "C:\Program Files\Bonjour\mdnsNSP.dll" |
Select-Object FullName,Length,CreationTime,LastWriteTime
```

The result showed:

```text
FullName       : C:\Program Files\Bonjour\mdnsNSP.dll
Length         : 132968
CreationTime   : 30/8/2011 23:05:32
LastWriteTime  : 30/8/2011 23:05:32
```

The file therefore had metadata identifying it as:

```text
C:\Program Files\Bonjour\mdnsNSP.dll
```

The timestamps on the DLL itself were from 2011, while the installation evidence for Bonjour on the computer was from 2026.

This demonstrated why file timestamps and installation timestamps should not automatically be treated as the same thing.

---

## 11. Verifying the Digital Signature

I then checked the Authenticode signature:

```powershell
Get-AuthenticodeSignature "C:\Program Files\Bonjour\mdnsNSP.dll" |
Format-List
```

The signature information showed:

* Signer: **Apple Inc.**
* Issuer: **VeriSign Class 3 Code Signing 2010 CA**
* Signature status: **Valid**
* Status message: **Signature verified**
* Signature type: **Authenticode**
* `IsOSBinary`: `False`

The file was therefore verified as an Apple-signed DLL.

I also observed that the signing certificate itself had dates from 2011–2013. This did not by itself invalidate the file because the signature contained timestamping information.

The important conclusion was:

> The DLL was digitally signed by Apple and Windows successfully verified the signature.

This did **not** by itself prove that the file was harmless, nor did the Code Integrity events prove that it was malware.

---

## 12. Establishing the Product Information

I checked the version and product information:

```powershell
(Get-Item "C:\Program Files\Bonjour\mdnsNSP.dll").VersionInfo |
Select-Object FileVersion,ProductVersion,CompanyName,ProductName
```

The result was:

```text
FileVersion   : 3,0,0,10
ProductVersion: 3,0,0,10
CompanyName   : Apple Inc.
ProductName   : Bonjour
```

This provided another independent piece of evidence identifying the DLL as part of Apple Bonjour.

---

## 13. Establishing When Bonjour Was Installed

I then examined the Windows uninstall information:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Where-Object {$_.DisplayName -like "*Bonjour*"} |
Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation
```

The result showed:

```text
DisplayName     : Bonjour
DisplayVersion  : 3.0.0.10
Publisher       : Apple Inc.
InstallDate     : 20260929
InstallLocation : C:\Program Files (x86)\Bonjour\
```

This established that the installed Bonjour product was version **3.0.0.10** and that Windows recorded its installation date as **29 September 2026**.

---

## 14. Establishing the Installation Source

I examined the complete Bonjour uninstall entry:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Where-Object {$_.DisplayName -eq "Bonjour"} |
Format-List *
```

One field was particularly important:

```text
InstallSource : C:\Program Files\Wondershare\drfone\
```

The uninstall information also showed:

```text
DisplayVersion : 3.0.0.10
Publisher      : Apple Inc.
InstallDate    : 20260929
```

The `InstallSource` provided a strong provenance link between the Bonjour installation and the Wondershare Dr.Fone installation directory.

However, I kept the distinction between:

> **installation source**

and

> **exact process that initiated the installation.**

The registry entry did not by itself identify the initiating process.

---

## 15. Correlating Dr.Fone

I then checked the 32-bit uninstall registry location for Dr.Fone:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
Where-Object {$_.DisplayName -like "*Dr.Fone*"} |
Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation
```

The result showed:

```text
DisplayName     : Wondershare Dr.Fone
DisplayVersion  : 13.9.9.818
Publisher       : Wondershare Technology Co.,Ltd.
InstallDate     : 20260929
InstallLocation : C:\Program Files\Wondershare\drfone\
```

This produced a meaningful installation chain:

```text
29 September 2026
        ↓
Wondershare Dr.Fone 13.9.9.818 installed
        ↓
C:\Program Files\Wondershare\drfone\
        ↓
Bonjour installation source
        ↓
Bonjour 3.0.0.10
        ↓
mdnsNSP.dll
```

This was substantially stronger than simply seeing `mdnsNSP.dll` on the computer.

---

# Part C — Windows Service Installation

## 16. Correlating Event 7045

I searched the Windows System log for relevant activity:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='System'
    StartTime=(Get-Date '2026-09-29')
} | Where-Object {
    $_.Message -match 'LSA|mdnsNSP|Bonjour|blocked|Local Security Authority'
} | Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message |
Format-List
```

The relevant event was:

```text
TimeCreated      : 29/9/2026 13:32:25
Id               : 7045
ProviderName     : Service Control Manager
LevelDisplayName : Information
```

The event recorded:

```text
Service Name     : Bonjour Service
Service File Name: C:\Program Files\Bonjour\mDNSResponder.exe
Startup Type     : Auto Start
Account          : LocalSystem
```

This established that Windows recorded installation of the Bonjour service.

Again, I did not use Event 7045 to claim which process initiated the installation because the event itself did not establish that.

---

# Part D — Code Integrity Events

## 17. Investigating Event 3033

I then examined the Code Integrity operational log:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-CodeIntegrity/Operational'
    StartTime=(Get-Date '2026-10-03 17:00')
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match 'mdnsNSP|Bonjour|LSA|blocked|Local Security Authority'
} |
Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message |
Format-List
```

The search returned multiple Event ID **3033** records.

These were not one single event.

I observed activity at several different times:

```text
17:05:59
17:07:28
17:24:15
17:33:14
17:48:07
17:48:10
17:48:51
18:22:15
18:33:14
```

Some timestamps contained duplicate records, so I preserved the distinction between repeated records and separate timestamps.

---

## 18. Processes Associated With Event 3033

The Code Integrity events identified two important processes attempting to load `mdnsNSP.dll`.

### svchost.exe

Several events identified:

```text
svchost.exe
```

The failure involved the **Microsoft signing-level requirement**.

### MpDefenderCoreService.exe

Other events identified:

```text
MpDefenderCoreService.exe
```

These events involved the **Custom 3 / Antimalware signing-level requirement**.

This was an important distinction because the Code Integrity event was reporting a signing-policy failure in the context of the process attempting to load the DLL.

---

## 19. Understanding What Event 3033 Actually Proves

The event establishes that Windows Code Integrity determined that a process attempted to load `mdnsNSP.dll` and that the DLL did not satisfy the required signing level for that loading context.

It does **not** establish:

* that `mdnsNSP.dll` was malware;
* that the DLL was unsigned;
* that the DLL was forged;
* that `svchost.exe` was malicious;
* that `MpDefenderCoreService.exe` was malicious;
* that credentials were stolen;
* that LSA was successfully injected;
* that the computer was compromised.

This was especially important because I had already independently established that Windows could verify the DLL's Apple Authenticode signature.

Therefore these two facts can coexist:

```text
Apple Authenticode signature = Valid
```

and

```text
Code Integrity signing-level requirement = Failed
```

They are not contradictory.

The signing-level policy being enforced by Code Integrity is a more specific security requirement than simply asking whether the DLL has a valid Authenticode signature.

---

# Part E — Timeline Correlation

## 20. Building the Timeline

The evidence allowed me to build a more complete timeline:

```text
29 Sep 2026
    ↓
Wondershare Dr.Fone 13.9.9.818 recorded as installed
    ↓
Bonjour 3.0.0.10 recorded as installed
    ↓
Bonjour installation source points to
C:\Program Files\Wondershare\drfone\
    ↓
13:32:25
Windows Event 7045 records Bonjour Service installation
    ↓
Bonjour service:
C:\Program Files\Bonjour\mDNSResponder.exe
    ↓
3 Oct 2026
    ↓
Code Integrity Event 3033 occurrences
    ↓
svchost.exe attempts to load mdnsNSP.dll
    ↓
MpDefenderCoreService.exe attempts to load mdnsNSP.dll
    ↓
Code Integrity rejects the load under the applicable signing-level policy
```

This timeline connected information from different Windows evidence sources rather than interpreting each event in isolation.

---

# Part F — Evidence Gaps

## 21. What I Established

At this point I had established that:

* `mdnsNSP.dll` existed at `C:\Program Files\Bonjour\mdnsNSP.dll`.
* Its metadata identified it as Apple Bonjour version `3.0.0.10`.
* Windows verified its Apple Authenticode signature.
* Bonjour was recorded as installed on **29 September 2026**.
* The Bonjour installation source pointed to the Wondershare Dr.Fone directory.
* Wondershare Dr.Fone version `13.9.9.818` was also recorded as installed on **29 September 2026**.
* Windows Event 7045 recorded installation of the Bonjour Service.
* Code Integrity Event 3033 recorded multiple attempts to load `mdnsNSP.dll`.
* Both `svchost.exe` and `MpDefenderCoreService.exe` were identified in those Code Integrity events.
* The load attempts failed the signing-level requirements applicable to those processes.

---

## 22. What I Could Not Yet Establish

The investigation did not yet establish:

* the exact process that installed Bonjour;
* the exact reason `svchost.exe` attempted to load `mdnsNSP.dll`;
* the exact reason `MpDefenderCoreService.exe` attempted to load it;
* whether the attempts were part of normal Windows/application behavior;
* whether a particular application triggered the loading;
* whether the activity was related to Local Security Authority beyond the fact that the investigation was initially prompted by a security warning involving that area.

These remained evidence gaps rather than conclusions.

---

# 23. Additional Log Validation

While investigating the Windows logs, I also confirmed that the relevant operational logs existed on the system.

The available logs included:

```text
System
Security
Application
Microsoft-Windows-LSA/Operational
Microsoft-Windows-CodeIntegrity/Operational
Microsoft-Windows-Windows Defender/Operational
Microsoft-Windows-Application-Experience/Program-Compatibility-Assistance
```

I also observed the approximate record counts for several logs, including:

```text
System                              14,684
Security                            34,393
Application                          6,959
CodeIntegrity/Operational            1,409
Windows Defender/Operational         1,502
Application-Experience/Program...       69
```

This reinforced the earlier Splunk lesson:

> Before concluding that evidence is missing, verify that the relevant Windows log exists, is enabled, contains records, and is being collected into the SIEM.

---

# 24. Investigation Methodology Learned

The main learning from this stage was that SOC investigation happens at several levels.

### Level 1 — Data existence

Is the data actually being collected?

### Level 2 — Search validity

Am I searching the correct index, sourcetype, EventCode, fields and time range?

### Level 3 — Event interpretation

What does the event itself actually establish?

### Level 4 — Correlation

Can another event, process, timestamp or configuration record support the interpretation?

### Level 5 — Evidence gaps

What important question remains unanswered?

This prevented me from jumping directly from:

```text
Event 3033
```

to:

```text
Malware
```

or from:

```text
No search result
```

to:

```text
No event occurred
```

---

# 25. Assessment

This investigation expanded my understanding of SIEM analysis beyond simply searching for suspicious events.

I learned that **the reliability of an investigation depends on validating the data source before interpreting the data**.

The Splunk investigation taught me to verify indexes, sourcetypes, EventCodes, time ranges and event coverage before treating a missing search result as evidence.

The Windows investigation then required the same evidence-first approach at the endpoint level. I correlated registry installation information, file metadata, digital signatures, Windows Service Control Manager events and Code Integrity events.

The evidence established a relationship between:

```text
Wondershare Dr.Fone
        ↓
Bonjour
        ↓
mdnsNSP.dll
        ↓
Code Integrity load attempts
```

But the evidence did not yet establish why the later processes attempted to load the DLL.

I therefore stopped at the evidence boundary rather than inventing an explanation.

---

# 26. Current Investigation Status

The investigation remains **partially resolved**.

### Established

* Splunk contains substantial Windows Security data.
* The apparent missing-event problem required index/search validation.
* Windows Security Event 4688 and related events can be investigated through the collected data.
* Bonjour 3.0.0.10 was installed on 29 September 2026.
* Its installation source points to the Wondershare Dr.Fone directory.
* Dr.Fone 13.9.9.818 was also installed on 29 September 2026.
* Bonjour Service installation was recorded by Event 7045.
* `mdnsNSP.dll` is Apple-signed and its Authenticode signature verifies.
* Multiple Code Integrity Event 3033 records occurred on 3 October 2026.
* `svchost.exe` and `MpDefenderCoreService.exe` were associated with attempts to load the DLL.
* Code Integrity rejected those loads because the DLL did not satisfy the required signing-level policy in those contexts.

### Unresolved

The main remaining question is:

> **Why did `svchost.exe` and `MpDefenderCoreService.exe` attempt to load `mdnsNSP.dll`?**

That question requires further correlation rather than assumption.

---

# 27. Key SOC Lesson

The most important lesson I carried forward from this investigation was:

> **Evidence must be validated before it is interpreted, and interpretation must stop where the evidence stops.**

A SIEM analyst is not only looking for events.

I must also establish:

**Where did the data come from?
Was the data collected correctly?
Did I search it correctly?
What does the event actually prove?
What can I correlate with it?
What remains unknown?**

This investigation reinforced the methodology I am building into my SOC learning:

**Event → Context → Timeline → Correlation → Hypothesis → Verification → Evidence Gap**
