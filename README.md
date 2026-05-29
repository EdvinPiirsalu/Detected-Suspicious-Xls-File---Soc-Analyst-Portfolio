# SOC138 — Detected Suspicious XLS File
SOC investigation writeup based on a real **LetsDefend.io** alert.

---

## Introduction

I received a SIEM alert detecting a suspicious XLS file. Before jumping into the investigation, I always make sure I fully understand what I'm dealing with.

An XLS file is simply a Microsoft Excel spreadsheet used to store and organize data. So why would a spreadsheet trigger a malware alert?


XLS files can contain macros (small scripts embedded inside the file that run automatically once you open it and allow execution). Think of it like a script hidden inside a spreadsheet. Attackers abuse this by embedding malicious macros that can:
- Download and execute malware silently in the background
- Establish a connection to the attacker's remote server (C2)
- Steal credentials or install backdoors
- Give the attacker full remote access to the machine

Attackers typically deliver these files via phishing emails, disguised as legitimate business documents which is what we see in this case.

---

<img width="2193" height="1092" alt="1" src="https://github.com/user-attachments/assets/b74783f6-1558-44cc-94d8-cb188b543ae2" />

Two things immediately stand out:

1. Device Action: "Allowed" -> the file was not blocked. It reached the machine.
2. After working hours timestamp -> 08:20 PM on a weekend raises suspicion as usual business activity at that time is unlikely.

---

## Investigation

### Step 1 — Understanding the File

The file name **"ORDER SHEET & SPEC.xlsm"** is a classic social engineering tactic, it looks like a usual business document. However the ".xlsm" extension is a red flag. The difference:

- `.xlsx` = data only, no code
- `.xlsm` = data + hidden macro code that executes on your machine

Additionally, the file was **password protected with the password "infected"**, a well known sandbox evasion technique. Here's why this matters:

When a suspicious file arrives, security systems throw it into a **sandbox** (an isolated environment that opens the file automatically and watches what it does). If the file is password protected, the sandbox cannot open 
it, cannot see the macro code, and lets it through. The attacker sends the password separately in the phishing email, so only the human victim can open it, while the automated security tools ignores it.

---

### Step 2 — Log Management Check

<img width="2121" height="607" alt="2" src="https://github.com/user-attachments/assets/930d00c7-ad34-45b6-8ecc-d3cc8d47f98d" />

3 results appeared. Two entries dated **March 13, 2021 at 08:20 PM** exactly matching the alert timestamp and both showing outbound connections from Sofia to the external IP **177.53.143.89** on **port 443**.

Port 443 is the standard HTTPS port. Attackers use it because encrypted traffic on port 443 blends in with normal web browsing, making it much harder to detect.

Opening the raw log revealed encrypted data:

<img width="2100" height="652" alt="3" src="https://github.com/user-attachments/assets/d32ba3eb-1780-4e64-8630-b2489eea7249" />

<img width="2117" height="762" alt="4" src="https://github.com/user-attachments/assets/6254609d-96bb-44de-80e7-30a64c29b8b1" />

The traffic being encrypted is expected on port 443 (HTTPS), but observing that Sofia initiated an outbound connection to an unknown external IP at the exact moment the malicious file was detected raises suspicion. This is the macro executing and calling out to the attacker's C2 server.

---

### Step 3 — Hash Analysis (VirusTotal)

I submitted the MD5 hash `7ccf88c0bbe3b29bf19d877c4596a8d4` to VirusTotal.

<img width="2527" height="1222" alt="5" src="https://github.com/user-attachments/assets/fa9128fd-31fb-4278-948b-1220d990cd6f" />

<img width="1267" height="1218" alt="6" src="https://github.com/user-attachments/assets/a087a533-f2aa-4765-8c35-4f83680996e4" />

Multiple vendors flagged the file as malicious, and the file name "ORDER SHEET & SPEC.xlsm" appeared in the known malicious file names list. This confirms the file is a known threat, not a false positive.

---

## Indicators of Compromise (IOCs)

MD5 Hash: `7ccf88c0bbe3b29bf19d877c4596a8d4` -> Malicious xlsm file
File Name `ORDER SHEET & SPEC.xlsm` -> Malware delivery document
IP Address `177.53.143.89` -> C2 server contacted after execution
IP Address `172.16.17.56` -> Compromised host (Sofia)

---

## Containment


This is enough evidence to decide that this xsl file is indeed malicious and needs to be contained. Below will be the steps taken to contain the malicious file.

<img width="1122" height="508" alt="8" src="https://github.com/user-attachments/assets/5076f42f-05b0-4b57-9688-eaf32b342dcf" />
Unknown or unexpected outgoing internet traffic detected.


<img width="988" height="462" alt="9" src="https://github.com/user-attachments/assets/af0822b7-d32b-4622-bdad-ea5eec21ce08" />
File was not quarantined, device action was allowed.


<img width="982" height="530" alt="10" src="https://github.com/user-attachments/assets/fa224869-f476-4d6c-929d-b08cc97b27a9" />
File confirmed malicious via VirusTotal.


<img width="977" height="518" alt="11" src="https://github.com/user-attachments/assets/afda077a-52b6-4ac9-bee8-53e936e55a23" />
C2 address confirmed accessed, Sofia made outbound contact with the attacker's server.


<img width="2052" height="827" alt="13" src="https://github.com/user-attachments/assets/945c6982-aaea-47dd-ba7a-24ff6128da54" />

<img width="987" height="477" alt="12" src="https://github.com/user-attachments/assets/cc351de4-88cc-4aa5-91dd-e9bc7bbd25a3" />
Host Sofia contained.

<img width="2135" height="657" alt="16" src="https://github.com/user-attachments/assets/03b0e01d-95ef-4fe4-9a79-67f08f0d14cb" />

<img width="977" height="717" alt="14" src="https://github.com/user-attachments/assets/884ff0c9-b7e2-4a50-940c-017b78e4f211" />
Contained.

---

## Analyst Notes

The alert was triggered by a suspicious macro enabled Excel file (ORDER SHEET & SPEC.xlsm) that reached host Sofia (172.16.17.56) on March 13 2021 at 20:20. The file used a password protection technique (password: "infected") to bypass automated sandbox analysis (evasion tactic). Device action was allowed, meaning it was not blocked and reached the system. Firewall logs confirm Sofia initiated an outbound connection to external IP 177.53.143.89 on port 443 at the exact time of the alert, strongly indicating the macro executed and established a C2 connection. Hash analysis via VirusTotal confirmed the file as a known malicious sample.

## Verdict

**True Positive** -> Host Sofia isolated and removed from network -> Escalation to Tier 2 recommended.
