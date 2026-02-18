# Phishing Email & Malware Investigation
## Overview

This project documents a SOC-style investigation involving a suspicious email attachment that resulted in a malware alert on an endpoint.

The objective was to analyze the email, assess the malicious attachment, respond to host alerts, and investigate execution activity using timeline analysis.

## Tools Used

- Email Header Analysis
- Endpoint Detection & Response (EDR) Alerts
- Host Timeline Analysis
- Process Investigation
- Quarantine & Containment Procedures
- NIST Incident Response Framework 

## Investigation Summary

During analysis, the following activity was observed:

User received a phishing email with an attachment
Attachment was downloaded to host
EDR generated malware alert
One host did not execute the file and was quarantined
A second host executed the file and required deeper investigation

## Timeline analysis revealed:

Suspicious file execution
Malicious DNS query

The activity was consistent with phishing-based malware delivery and post-exploitation behavior.

## Investigation Walkthrough

## Investigation 1 — Phishing Email Analysis

### Objective

The goal was to determine whether the email attachment was malicious and assess potential risk to the environment.

### Step 1 — Analyze the Email

The email contained:

An attachment labeled as a legitimate document

Indicators of phishing characteristics

Social engineering elements

The attachment was downloaded for analysis.

![Email_attachment](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/email_attachment.png)


## Investigation 2 — Malware Alert & Initial Response

### Objective

Determine which hosts were affected and prevent further spread.

Step 1 — Review Security Alert

An endpoint security alert indicated malware detection on the host after the attachment download.

![Malware_detected](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/malware_detected.png)

Two scenarios were identified:

Host 1 and 2

Attachment downloaded

File did not execute

Files quarantined successfully

Host 3

Attachment downloaded

File executed

Required deeper investigation

![Quarantine_files](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/quarantine_files.png)

## Investigation 3 — Timeline Analysis of Infected Host

###Objective

Understand what occurred after execution of the malicious file.

Step 1 — Review Process Timeline

The investigation timeline showed:

explorer.exe
→ chrome.exe
→ File downloaded
→ Payslip.pdf
→ Execution
→ Malicious DNS query

This sequence indicated:

User browsing activity

Download of malicious attachment

Execution of disguised file

Command-line activity

Potential command-and-control (C2) communication

You can include your timeline image like this:

![Execution Timeline](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/timeline.png)
Findings

The malicious attachment initiated:

Suspicious command-line execution

Network communication to malicious domain

Behavior consistent with phishing-delivered malware

The attack chain followed a common pattern:

Initial Access → Execution → Command & Control

Response Actions Taken

Quarantined malicious files
Isolated affected host
Prevented further execution
Preserved logs for analysis

Incident Classification

Phishing Attack
Malware Execution
Potential Command & Control Activity

Lessons Learned

Strengthen email filtering
Block malicious domains at DNS level
Enforce attachment sandboxing
Improve user phishing awareness training
Enhance monitoring of command-line activity
