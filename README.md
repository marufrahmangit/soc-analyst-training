# SOC ANALYST TRAINING
Learning sources: 
- Mini-training course: https://youtu.be/GxFBa-wfSbs?si=tNhBAl6QeIHStnro
- Udemy: https://www.udemy.com/course/cyber-security-soc-analyst-training-siem-splunk-60-hrs/?referralCode=C89A70FBEB632AB7752C (used chatgpt to study topics)
- Splunk: https://youtu.be/LbR5cqqaFVk?si=eRHQoE0p1RfNVKqL

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

Free SIEM Tool: [**Security Onion**](https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhqbnlHQ3pVOWpaTzdKY0JsYTdHRktiYTNTNUJfQXxBQ3Jtc0ttQUFVU19CcG9ITDJnNXo5VENYSHJCZy0yUE1DM01vSGlUNDBOTFRxVGdtXzYxa0UtdWRlMnRRaVZhRWU5T283UDg2bVNJQjl3SFBDZV9OQ0lQVlRMeWVyWDVkVHl2SFVJejZaNWwzZzJORjZOR0tFcw&q=https%3A%2F%2Fgithub.com%2FSecurity-Onion-Solutions%2Fsecurityonion%2Fblob%2F2.4%2Fmain%2FDOWNLOAD_AND_VERIFY_ISO.md&v=GxFBa-wfSbs)

# ISO Model
Think of the ISO model like a 7-layer cake. Each layer has its job in helping computers talk to each other. The layers are:

Physical - wires and signals.
Data Link - rules for sending data.
Network - addresses for where data goes.
Transport - making sure data is whole.
Session - managing conversations.
Presentation - making data readable.
Application - programs we use.

# Public/Private Address Range/Subnetting
Imagine your house has a street address (public) and rooms inside with different door numbers (private). Subnetting is like organizing rooms into groups, so you know where everything is.

# HTTP and Understanding Service Ports
HTTP is how your browser talks to websites, like asking for a page. Ports are like doorways on your computer; different doors (ports) are used for different tasks.

# SMB, SMTP, Telnet, SSH, FTP, SMTP, MySQL Services
These are like different tools for talking between computers:

- SMB: sharing files.
- SMTP: sending emails.
- Telnet: talking to another computer from far away.
- SSH: talking securely to another computer.
- FTP: moving files.
- MySQL: storing and organizing data.

# Cyber Kill Chain / Phases of Attack
This is like the steps a bad guy takes to break into your house:

- Recon - looking at your house.
- Weaponization - picking a tool to break in.
- Delivery - bringing the tool to your house.
- Exploitation - using the tool to break in.
- Installation - setting up inside your house.
- Command and Control - controlling from afar.
- Actions on Objectives - stealing stuff.

# Brute Force Attack and Types
Imagine guessing a password by trying every combination until you get it right. That's a brute-force attack. It can happen quickly or slowly, and sometimes, attackers guess more than just passwords.

# Phishing and Spoofing Attacks
Phishing is like someone pretending to be your friend to steal your candy. Spoofing is like someone changing their appearance to trick you into thinking they're someone else.

# OWASP Top 10
This is a list of the 10 most common ways bad guys can mess with websites, like:

- Injection - sneaking in bad code.
- Broken Authentication - weak password rules.
- Sensitive Data Exposure - leaking secrets. …and more!

# DNS Tunneling Attack
Think of this as someone secretly sending messages through a tunnel underneath your house without you knowing. It’s hidden in normal traffic.

# Malware and its Types
Malware is like a bad guy hiding inside a toy to mess up your stuff. Types include:

- Virus: spreads to other toys.
- Worm: moves by itself.
- Trojan: pretends to be good.
- Ransomware: locks your toys and asks for money.

# SIEM Use Cases
SIEM is like a security guard watching cameras and alarms in your house, spotting and reacting to anything weird.

# Windows OS - Computer Management, Utilities
- Device Manager: This tool is like a checklist for all the devices (like printers, keyboards, and monitors) connected to your computer. If something isn't working right, you can check here to see if there's a problem with one of the devices.
- Disk Management: Think of this tool as a map of all the storage spaces (like hard drives) in your house. It helps you see how much space you have, organize it (like making a new room by partitioning), or even change the way the space is used.
- Task Scheduler: This is like a planner that helps you schedule tasks automatically. You can set it to clean up your house (run maintenance tasks), water the plants (run backups), or do other chores at specific times without you needing to remember.
-Event Viewer: The Event Viewer is like a security camera log for your house. It records everything that happens (good and bad) so you can check later if something goes wrong or just see what’s been going on.
- Performance Monitor: This tool is like a fitness tracker for your house. It monitors how well everything is running, like checking if the power (CPU) is being used too much or if there’s too much traffic in the hallways (memory and network usage).
- Services: These are like the different utilities (like electricity or water) running in your house. The Services tool lets you start, stop, or change how these utilities work, like deciding when to turn the heat on or off (starting or stopping a service).
- System Information: This is like a blueprint of your house that shows all the details about what’s inside, like how big each room is (memory), what materials were used (hardware), and how everything is set up (system configuration).
- Task Manager: Task Manager is like a quick list of everything happening in your house right now—what rooms are in use (applications running), how much energy is being used (CPU and memory), and who’s using it (which applications are responsible).

# Incident Handling Stages
If something bad happens, you:

- Prepare - get ready.
- Identify - spot the problem.
- Contain - stop it from spreading.
- Eradicate - remove the problem.
- Recover - fix what’s broken.
- Learn - make sure it doesn’t happen again.

# Malware Outbreak Analysis
This is like figuring out how a bad guy snuck in, what damage they did, and how to stop them next time.

# Threat Hunting - Scanning Attack on Web Server, Brute Force Attack
Threat hunting is like searching for bad guys hiding in your house. You look for signs of forced entry (brute force) or sneakiness (scanning).

**Identify Indicators of Scanning**:
- Unusual spikes in network traffic directed at the web server.
- Repeated access attempts to various ports in quick succession.
- Access requests from a single IP address to multiple URLs or resources.
  
**Log Analysis**:
- Analyze web server logs for patterns that indicate systematic probing (e.g., multiple 404 or 403 error codes from the same IP).
- Use intrusion detection/prevention systems (IDS/IPS) logs to identify any detected scanning activities.
  
**Network Traffic Analysis**:
- Monitor for unusual network traffic patterns, such as large numbers of SYN packets without corresponding ACK packets, which could indicate a port scan.
- Utilize network flow data to identify traffic anomalies that align with scanning behavior.
  
**Response Actions**:
- Block the source IP if it's determined to be malicious.
- Implement rate limiting or CAPTCHA challenges to slow down or thwart automated scans.
- Review and harden the web server's security posture, including closing unnecessary ports and services.

**Identify Indicators of Brute Force Attempts**:
- Multiple failed login attempts from the same IP address over a short period.
- Unusual spikes in login attempts, particularly on specific accounts.
- Login attempts with common usernames (e.g., "admin," "root") or default credentials.
  
**Log Analysis**:
- Examine authentication logs for patterns of repeated failed login attempts.
- Look for login attempts from unusual geographic locations or IP addresses.
  
**Network Traffic Analysis**:
- Monitor for high volumes of traffic to the login endpoint of a web application.
- Analyze network traffic for patterns that suggest automated tools are being used to perform the attack.
  
**Response Actions**:
- Temporarily block or blacklist the IP address if the attack is ongoing.
- Implement account lockout mechanisms after a defined number of failed login attempts.
- Enforce strong password policies and multi-factor authentication (MFA) to make brute force attacks more difficult.
- Notify the affected user and prompt them to reset their password if their account was targeted.

# Email Header Analysis
Reading an email header is like checking the return address on an envelope to see where it really came from and if it’s safe to open.

