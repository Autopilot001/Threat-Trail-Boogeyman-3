# Threat Trail: Boogeyman 3

**Author:** Mohamed Nabil Algamoudi  
**Original room title:** Boogeyman 3  TryHackMe  
**Focus:** Phishing investigation and Windows endpoint triage in Elastic

## Scope

I reviewed the evidence from the assigned TryHackMe room and followed the incident through the supplied Elastic screenshots. The screenshots show a phishing attachment, suspicious Windows process activity, network telemetry, credential access activity, and a ransomware process. I kept the investigation searches and useful process context visible. Public copies obscure IP addresses and contact details, along with encoded malware content and credential dumping arguments.

## Investigation

### I reviewed the reported email

The incident began with an urgent financial-document email sent to the CEO. The message asked for a quick review of an attachment. The recipient opened it despite doubts and then reported the email. I treated that report as the starting point for the endpoint investigation.

<details>
<summary>Screenshot: Step 1 — Reported phishing email; contact details obscured</summary>

<img src="../screenshots/step-01.png" alt="Step 1 — Reported phishing email; contact details obscured" width="760">

</details>

### I located the attachment and checked the mounted image

In the Downloads evidence, I found the ISO named `ProjectFinancialSummary_Q3.pdf`. After mounting it, I saw a file with the same name whose actual type was **HTML Application**. That mismatch made the attachment suspicious and gave me a filename and file type to search for in Elastic.

<details>
<summary>Screenshot: Step 2  Downloaded ISO and mounted file type</summary>

<img src="../screenshots/step-02.png" alt="Step 2 — Downloaded ISO and mounted file type" width="760">

</details>

<details>
<summary>Screenshot: Step 3  Second capture of the attachment evidence</summary>

<img src="../screenshots/step-03.png" alt="Step 3 — Second capture of the attachment evidence" width="760">

</details>

### I set the incident time window

I narrowed the Elastic time picker to August 29, 2023 at 00:00 through August 30, 2023 at 23:30, matching the incident window shown in the room evidence.

<details>
<summary>Screenshot: Step 4  Elastic investigation time range</summary>

<img src="../screenshots/step-04.png" alt="Step 4 — Elastic investigation time range" width="760">

</details>

### I searched for the HTML attachment

I searched the `winlogbeat-*` data for HTML file activity. The screenshot shows the KQL filter `file.extension: html` and a process event associated with the suspicious attachment.

```kql
file.extension: "html"
```

<details>
<summary>Screenshot: Step 5  HTML file search in Elastic</summary>

<img src="../screenshots/step-05.png" alt="Step 5 — HTML file search in Elastic" width="760">

</details>

### I traced the attachment process chain

The event details identify `mshta.exe` as the HTML Application process. I then reviewed nearby records to understand what followed it rather than treating the attachment event in isolation.

<details>
<summary>Screenshot: Step 6  HTML Application process event</summary>

<img src="../screenshots/step-06.png" alt="Step 6 — HTML Application process event" width="760">

</details>

<details>
<summary>Screenshot: Step 7 Related process and network events in the timeline</summary>

<img src="../screenshots/step-07.png" alt="Step 7 — Related process and network events in the timeline" width="760">

</details>

The process telemetry records `xcopy.exe` copying `D:\review.dat` into the user’s temporary directory. I used the copy event as a link between the mounted attachment and the next execution event.

<details>
<summary>Screenshot: Step 8  Copy command recorded in process telemetry</summary>

<img src="../screenshots/step-08.png" alt="Step 8 — Copy command recorded in process telemetry" width="760">

</details>

<details>
<summary>Screenshot: Step 9 Additional view of the file-copy event</summary>

<img src="../screenshots/step-09.png" alt="Step 9 — Additional view of the file-copy event" width="760">

</details>

The next event shows `rundll32.exe` loading `D:\review.dat` with the `DllRegisterServer` entry point. I treated this as execution evidence for the file copied in the preceding event.

```text
rundll32.exe D:\review.dat,DllRegisterServer
```

<details>
<summary>Screenshot: Step 10  DLL registration activity in process telemetry</summary>

<img src="../screenshots/step-10.png" alt="Step 10 — DLL registration activity in process telemetry" width="760">

</details>

I also reviewed a PowerShell process event that creates a scheduled task using `rundll32.exe`. That gave me a persistence lead to correlate with the rest of the timeline.

<details>
<summary>Screenshot: Step 11  Scheduled-task process event</summary>

<img src="../screenshots/step-11.png" alt="Step 11 — Scheduled-task process event" width="760">

</details>

<details>
<summary>Screenshot: Step 12  Expanded details for the rundll32 event</summary>

<img src="../screenshots/step-12.png" alt="Step 12 — Expanded details for the rundll32 event" width="760">

</details>

### I reviewed the network and elevated PowerShell activity

Elastic recorded an HTTP connection from the affected host to an external address. I covered both IP addresses in the public screenshot while retaining the process, protocol, and event context.

<details>
<summary>Screenshot: Step 13  HTTP connection event; IP addresses obscured</summary>

<img src="../screenshots/step-13.png" alt="Step 13 — HTTP connection event; IP addresses obscured" width="760">

</details>

Another process record shows hidden PowerShell launched in the context of `fodhelper.exe`. I treated the parent process, hidden window flags, and encoded-command pattern as suspicious. The obfuscated command body is covered in the public copy.

<details>
<summary>Screenshot: Step 14  PowerShell process and fodhelper parent</summary>

<img src="../screenshots/step-14.png" alt="Step 14 — PowerShell process and fodhelper parent" width="760">

</details>

<details>
<summary>Screenshot: Step 15  Elastic engine state event in the incident timeline</summary>

<img src="../screenshots/step-15.png" alt="Step 15 — Elastic engine state event in the incident timeline" width="760">

</details>

### I searched for credential-access activity

The August 30 events show `mimikatz.exe` and PowerShell activity associated with credential access. I used the process name as a focused Elastic search, then reviewed the matching event details. I masked the credential-dumping arguments and encoded payload while leaving the search and process context visible.

<details>
<summary>Screenshot: Step 16  Mimikatz process event</summary>

<img src="../screenshots/step-16.png" alt="Step 16 — Mimikatz process event" width="760">

</details>

<details>
<summary>Screenshot: Step 17  Related PowerShell event</summary>

<img src="../screenshots/step-17.png" alt="Step 17 — Related PowerShell event" width="760">

</details>

<details>
<summary>Screenshot: Step 18  Credential-access PowerShell records; sensitive arguments obscured</summary>

<img src="../screenshots/step-18.png" alt="Step 18 — Credential-access PowerShell records; sensitive arguments obscured" width="760">

</details>

<details>
<summary>Screenshot: Step 19  Expanded view of the related process event</summary>

<img src="../screenshots/step-19.png" alt="Step 19 — Expanded view of the related process event" width="760">

</details>

The process record also contains an encoded PowerShell command. I kept the executable and `-enc` indicator visible but covered the encoded value.

<details>
<summary>Screenshot: Step 20  Encoded PowerShell process; payload obscured</summary>

<img src="../screenshots/step-20.png" alt="Step 20 — Encoded PowerShell process; payload obscured" width="760">

</details>

I narrowed the Elastic results to the Mimikatz process name. The query returned 11 hits in the shown time range. I kept the KQL filter visible and obscured command-line values that contained credential-access arguments.

```kql
process.name: "mimikatz.exe"
```

<details>
<summary>Screenshot: Step 21  Mimikatz search results; IP and sensitive process arguments obscured</summary>

<img src="../screenshots/step-21.png" alt="Step 21 — Mimikatz search results; IP and sensitive process arguments obscured" width="760">

</details>

<details>
<summary>Screenshot: Step 22  Expanded Mimikatz event details; sensitive values obscured</summary>

<img src="../screenshots/step-22.png" alt="Step 22 — Expanded Mimikatz event details; sensitive values obscured" width="760">

</details>

### I identified the ransomware process

The final supplied event records creation of `ransomboogey.exe` on the domain controller. I used this as the endpoint evidence that the incident progressed from the initial attachment to ransomware activity.

<details>
<summary>Screenshot: Step 23  Ransomware process event</summary>

<img src="../screenshots/step-23.png" alt="Step 23 — Ransomware process event" width="760">

</details>

## Reflection

This investigation reinforced how useful a clear time window and process lineage are during incident response. I connected the attachment to HTML handling, file staging, DLL loading, persistence, credential-access activity, and the ransomware process by following the events through Elastic. In a real environment, I would isolate affected systems, preserve logs and artifacts, block the observed infrastructure, reset exposed credentials, and verify recovery from clean backups.

