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

![Quarantine_files](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/quarantine_files.png)

Host 3

Attachment downloaded

File executed

Required deeper investigation

![Investigate_hosts](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/investigate_host.png)

## Investigation 3 — Timeline Analysis of Infected Host

### Objective

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

![Execution Timeline](https://github.com/davidattah/Cybersecurity-portfolio/blob/main/Projects/02-siem-brute-force-investigation/screenshots/timeline.png)

### Findings

The malicious attachment initiated:

Suspicious command-line execution

Network communication to malicious domain

Behavior consistent with phishing-delivered malware

The attack chain followed a common pattern:

Initial Access → Execution → Command & Control

### Response Actions Taken:

Quarantined malicious files

Isolated affected host

Prevented further execution

Preserved logs for analysis

### Incident Classification

Phishing Attack

Malware Execution

Potential Command & Control Activity

## Lessons Learned:

To reduce the likelihood of similar incidents occurring in the future, I recommend implementing the following security improvements: 

- Strengthen Email Filtering - 

  Implement advanced email filtering and anti-phishing controls to detect and block malicious attachments and spoofed sender domains before they reach end users.

- Block Malicious Domains at DNS Level - 

  Use DNS filtering to prevent endpoints from resolving and communicating with known malicious or suspicious domains, reducing the risk of command-and-control activity.

- Enforce Attachment Sandboxing - 

  Deploy attachment sandboxing to automatically detonate and analyze email attachments in an isolated environment before delivery to users.

- Improve User Phishing Awareness Training - 

  Conduct regular security awareness training to help users identify phishing attempts and report suspicious emails promptly.

Enhance Monitoring of Command-Line Activity - 

Increase visibility into command-line execution by enabling detailed logging and alerting for suspicious PowerShell or script-based activity.


## Final Conclusion

Across this investigation, I was able to:

Analyze a suspicious email containing a potentially malicious attachment

Respond to endpoint security alerts by quarantining affected files and containing impacted hosts

Conduct a deeper investigation on the host where the file was executed

Perform timeline analysis to understand the attack sequence

Provide security recommendations to reduce the risk of similar incidents occurring in the future


