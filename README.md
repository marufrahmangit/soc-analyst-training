# SOC ANALYST MINI TRAINING COURSE
[course-link](https://www.youtube.com/watch?v=GxFBa-wfSbs)

## A SOC protects organizations from threats but most importantly *confidentiality*, *integrity*, and *availability* (CIA) of digital assets. 

# Key Functions of a SOC
Key functions include *monitoring*, *detecting*, and *responding*, however, what makes up a SOC are the *people*, *process*, and *technology*.

![image](https://github.com/user-attachments/assets/28b0e5ba-261c-44d5-9452-3b636160419a)

# SOC Roles
![image](https://github.com/user-attachments/assets/53bf058d-eb15-42a4-9169-85c112c4b5af)

# SOC Analyst responsibilities
![image](https://github.com/user-attachments/assets/00f4cf30-53ca-4681-ba03-90fdab4673b1)

# Common Threats
- Social Engineering: phishing, vishing (imposter/phone call), quishing (QR code phishing)
- Identity compromise: brute force, social engineering, credential dumps
- Malware: worm, spyware, adware, ransomware, trojan, fileless

# Frameworks
## NIST Incident Response Lifecycle

| Preparation →     | Detection & Analysis →   | Containment & Eradication →   | Post-Incident Activity   |
|-------------------|--------------------------|-------------------------------|----------------------------|
| Prioritize key assets. | Identify scope & impact. | Recovery steps.                | Review & improve.          |

## SANS Incident Response Lifecycle

![image](https://github.com/user-attachments/assets/d389d4bc-3f55-44bc-9d2c-3e839d60ebb8)

## Lockheed Marting Kill Chain
A list of phases an attacker will go through:
1. Reconnaissance: Harvesting email addresses, company information, etc.
2. Weaponization: Coupling exploit with a backdoor into the deliverable payload.
3. Delivery: Delivering weaponized Delivering weaponized bundle to the victim via email, web, USB, etc.
4. Exploitation: Exploiting a vulnerability to execute code on the victim's system.
5. Installation: Installing malware on the asset.
6. Command & Control (C2): Command channel for remote manipulation of the victim.
7. Actions on Objectives: With 'hands-on keyboard' access, intruders accomplish their original goals.

## MITRE ATT&CK framework
- Tactics: Initial access to a company.
- Techniques: Example, phishing.
- Procedures: Details and steps of the technique (includes sub-techniques).

# OSINT (Open Source Intelligence) Tools
### IP Reputation/Information
- Objective: To identify the potential usage for the IP Address of interest (i.e., how malicious or benign the IP is). The higher the reputation, the more likely the IP had been reported.
- Tool: VirusTotal, AbuseIPDB, GreyNoise, AlientVaultOTX, IBM X-Force Exchange, IPVoid, Bright Cloud, Cisco Talos.

### Domain Reputation/Information
- Objective: Quickly assess the legitimacy of a domain by identifying behavior and obtaining metadata of the domain of interest.
- Tool: VirusTotal, urlscan, AlientVaultOTX, IBM X-Force Exchange, URLVoid, Bright Cloud, Cisco Talos.

### File Reputation
- Objective: To identify a malicious file and understand its behavior.
- Tool: VirusTotal, Any.Run, Joe Sandbox, Hybrid Analysis, AlientVaultOTX, IBM X-Force Exchange, Cisco Talos.

### Threat Intelligence
- Objective: Attempt to reveal additional artifacts for additional pivot opportunities & to identify motive / actions on objective during an investigation.
- Tool: VirusTotal, PulseDrive, MITRE ATT&CK, AlientVaultOTX, MISP, Threat Miner, Robtex.

## Pyramid of Pain
Determines which Indicators of Compromise (IoC) are easy to change when it comes to an attacker:

![image](https://github.com/user-attachments/assets/7bc5dce1-abb1-4c8d-8a9d-814eaa413698)

# SIEM (Security Information and Event Management)
A solution that allows an organization to consolidate and aggregate data into a centralized location:
- Log Management: Centralized location, log retention, organized data.
- Correlation & Analysis: Alert/rule creation, identify anomalies, and remediate threats.
- Ticketing & Reporting: Case management, dashboard, audits and reports.

Free SIEM Tool: **Security Onion**

![image](https://github.com/user-attachments/assets/d28e9b39-acc2-4c5d-8b73-0c2d2ad5cfae)

