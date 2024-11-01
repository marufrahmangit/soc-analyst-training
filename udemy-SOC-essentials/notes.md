# SOC Essentials by SOC Experts
course link: https://www.udemy.com/course/soc-essentials/

## Different positions of security teams
**Endpoint/ host security** (user machines, serves, etc.): installing, configuring and maintaining endpoint security
- antivirus, host firewall, HIPS, disk encryption, DLP, EDR

**Network security**: installing, configuring and maintaining network security
- firewall, IPS, web gateway, email gateway, wireless security, WAP

**Information Security (GRC)**:
- conduct audits, security policies, user awareness training, adherence of company's infrastructure to regulatory compliance

**Vulnerability Assessment**: use of automation tools to identify vulnerabilities in applications and systems
- network scan, patching

**Identity and Access Management**: create and manage identities and access rights
- user accounts, password resets, granting access

**Security Operations Center**: monitor, detect, investigate, respond to cyber threats
- SIEM, SOAR, Threat Intelligence, Analysis Tools

## Identifying/Root Cause Analysis
**Log Monitoring**: 
- Systems/Servers, Security Solutions, Network Devices

**SIEM**: Identify suspicious activities from logs

**Cybersecurity Rule Enforcers**:
Regulatory Compliance/ Industry Best practices
- PCI DSS, GDPR, HIPAA

## What is SOC
- File line of defense
- Organization security
- Monitor, Detect, investigate, and respond to cyber threats
Monitor for alerts from SIEM > Analyze the alert > Decide if the alert is bad > legitimate: ignore/bad: report for corrective actions > help the team to stop any bad activity.

## SOC Building Blocks
- People
- Process
- Technology

### People
**L1 SOC Analyst** / certificates: `security+` `cysa+` `ceh` `gisp`
- 24/7 eyes-on-glass monitoring
- analysis of triggered alerts (usually following a playbook)
- raising tickets for validated incidents
- follow-up with incident response team for remediation
- drafting shift hand-overs
- assist L2/L3 in reporting

**L2 SOC Analyst** / certificates: `security+` `cysa+` `ceh` `gisp`
- deep dive analysis of escalated alerts
- assist in incident remediation
- assist L1 in alert analysis
- maintaining and improving Standard Operations of Procedure (SOP) and processes
- troubleshoot basic SIEM issues

**SOC Lead** / certificates: `cisa` `SIEM: splunk, IBM QRader, etc.`
- Installing, updating, and upgrading SIEM solutions
- On-boarding log sources and working on log source issues
- Creating and fine-tuning content in SIEM: correlation rules, dashboards, reports, lists, etc.
- Interacting with SIEM vendor TAC (support) to fix any issues with SIEM
- Installing, managing, and building content in SIEM
- Mentoring L1 and L2 security analysts
- Assisting in analysis that requires involvement of multiple teams
- Evaluating new solutions for SOC team
- Creating playbooks for all alerts
- Scheduling shift rosters

**SOC Manager** / certificates: `cisa` `cissp` `cism`
- Define the scope, vision, and direction for the SOC team
- Supervise the team, provide technical guidance, and manage financial activities
- Oversee the activity of the SOC team members, including hiring, training, and assessing staff
- Develop and improve processes and procedures for SOC team
- Ensure compliance to service level agreements (SLA) and process adherence
- Create compliance reports, support the audit process, and measure SOC performance metrics
- Vendor management
- Report on security operations to business leaders

**Threat Intel Researcher** / certificates: `ctia`
- Track and monitor vulnerability lifecycles from zero-day discovery to CVE-ID allocation and patch release
- Profile and monitor specified cyber threat actors, including nation-states, hacktivist groups, and campaigns to understand adversarial tradecraft along with TTPs
- Crawl the dark web and deep web to identify new breaches, data leaks, etc.
- Obtain, integrate, and share threat intelligence with security partners and vendors (i.e., search for known threats)
- Conduct research (OSINT, US-CERT, CVE MITRE, NVD, etc.) to generate new threat intelligence
- Communicate between the Intel team and content team to drive and improve prevention and detection
- Automatic threat sharing using STIX and TAXII

**Threat Hunter** / certificates: `ceh` `ctia` `elk stack`
- Log mining and identifying threats
- Track threat actors and associated tactics, techniques, and procedures (TTPs)
- Capture intelligence on threat actor TTPs and develop countermeasures in response to threat actors
- Analyze network traffic, IDS/IPS/DLP events, packet capture, and firewall logs
- Analyze malicious campaigns and evaluate the effectiveness of security technologies
- Develop advanced queries and alerts to detect adversary actions
- Coordinate threat hunting activities across the network leveraging intelligence from multiple internal and external sources and security technologies

**Incident Handler** / certificates: `security+` `ecih` `mcse` `linux+`
- Formulate and execute a response to the incident and verify that it is contained, eradicated, and systems are recovered
- Based on the review of the process and steps taken to remediate an incident, suggest and implement improvements in the environment (such as improving technical controls) and/or improve the incident response process
- Develop and update incident response playbooks to ensure response activities align with best practices, minimize gaps in response, and provide comprehensive mitigation of threats

**Forensic Specialist** / certificates: `chif` `ence (opentext)` `autopsy`
- Conduct forensic examinations on compromised computers and servers through application of scientific practices for recognition, collection, analysis, and interpretation of digital evidence
- Recover deleted emails, recover data that has been deleted or encrypted, and uncover passwords
- Establish and provide digital evidence for investigations and court proceedings
- Conduct large-scale investigations and examine endpoint and network-based sources of evidence
- Write complete, accurate, logical, consistent, grammatically correct, evidentiary-quality forensics reports that “**tell the story**” of the attack in a way that can be understood by tech and non-tech readers

**Red Team Specialist**/ certificates: `csa` `oscp`
- Continuously scan the network for weaknesses in systems, servers, network devices, or users
- Launch small-scale attacks (without business disruption)
- Build POCs for known vulnerabilities
- Develop phishing campaigns to test users
- Use social engineering techniques to evade existing security controls

**Automation Engineer**/ certificates: `python` `elk stack`
- Automate repeated tasks in SOC team
- Integrate disparate systems to make them work together
- Develop scripts that can be run on infected machines to collect machine state
- Automate analysis of triggered alerts using SOAR platform

### Process

### Technology
