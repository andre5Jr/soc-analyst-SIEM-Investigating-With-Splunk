📝 Project Title:

TryHackMe – Investigating with Splunk: Detecting Backdoor Activity

🎯 Objective:

Analyze Windows event logs ingested into Splunk from compromised hosts to detect backdoor user creation, unauthorized remote actions, and malicious PowerShell activity, ultimately identifying indicators of compromise.

🛠️ Tools Used:

Splunk (Search & Reporting)

Windows Event Logs

PowerShell Logging

Base64 decoding tools

❌ Skills Demonstrated:

Log analysis using Splunk queries

Registry key and user account forensics

Detection of remote admin activity

Decoding encoded PowerShell payloads

Threat hunting and behavioral correlation

Project Overview
This investigation simulates a real-world SOC analysis using Splunk to detect malicious activity across compromised Windows hosts. The task was prompted by suspicious behaviors observed by a fellow analyst, with logs indicating that an attacker created a backdoor user, tampered with registry keys, and executed obfuscated PowerShell scripts. All logs were centralized in Splunk under the main index for triage.

Task Breakdown

✏️ Task 1: Count Ingested Events

⭕️ Objective: Determine how many events were ingested into the main index.

⭕️ Method: Use Splunk Search: index=main | stats count

✏️ Task 2: Identify the Backdoor Username

⭕️ Objective: Find the unauthorized user created by the attacker.

⭕️ Method: Query for user creation events: index=main EventCode=4720 & Check TargetUserName field.

✏️ Task 3: Locate Registry Key Change

⭕️ Objective: Identify the registry path modified for persistence.

⭕️ Method: Search registry modification logs: index=main Registry & Filter by keywords like backup_admin

✏️ Task 4: Detect Impersonated User

⭕️ Objective: Find which legitimate user account was targeted for impersonation.

⭕️ Method:Investigate suspicious logon attempts: index=main EventCode=4648 & Look for attempts using high-privilege usernames.

✏️ Task 5: Command Used for Remote Backdoor Creation

⭕️ Objective: Identify the command used to create the backdoor user remotely.

⭕️ Method: Look for event logs showing remote command execution: index=main EventCode=4688 & Check for net user or psexec commands.

✏️ Task 6: Count Login Attempts by Backdoor User

⭕️ Objective: Determine how often the attacker tried logging in with the new user.

⭕️ Method: Search for logon attempts: index=main TargetUserName="backup_admin" EventCode=4624 OR EventCode=4625

✏️ Task 7: Identify Infected Host Running PowerShell

⭕️ Objective: Name the host that executed suspicious PowerShell commands.

⭕️ Method:Search for PowerShell usage logs: index=main powershell & Filter for suspicious commands.

✏️ Task 8: Count of Malicious PowerShell Events

⭕️ Objective: Count how many PowerShell logs were generated from the malicious execution.

⭕️ Method: Search: index=main host="DC1-THM-AD" process="powershell.exe"

✏️ Task 9: Identify the Full URL in PowerShell Request

⭕️ Objective: Find the full web address used in the PowerShell script.

⭕️ Method: Extract base64 strings and decode manually or via script & Look inside CommandLine field for encoded strings.

🔍 Analysis and Reflection
💡 Challenges Faced:

Isolating encoded PowerShell from benign scripts.

Navigating verbose logs to find meaningful signals.

Correlating user creation with registry persistence.

💡 Lessons Learned:

Registry key analysis is vital for detecting hidden users.

PowerShell logs often reveal clear indicators of attack.

Adversaries prefer creating stealthy users and disabling visibility.

💡 Relevance to SOC Analyst Roles:

Shows how lateral movement and backdoors appear in logs.

Enhances familiarity with Splunk’s search capabilities.

Builds real-world correlation and alert triage skills.

💡 Relevance to Penetration Testing / Red Teaming:

Highlights attacker TTPs involving backdoor user creation.

Offers a blueprint for mimicking persistent access techniques.

Underscores need for defenders to monitor encoded script behavior.

✅ Conclusion
💡 Summary:

Detected anomalous behavior from Windows event logs using Splunk. Identified unauthorized user backup_admin, uncovered registry persistence via UserList, tracked attacker impersonation, and analyzed encoded PowerShell used to download a payload from maliciousdomain.live.

💡 Skills Gained:

Windows event log triage in Splunk

User and registry change tracking

PowerShell script decoding

Detection of remote administration activity

💡 Next Steps:

Create Splunk alerts for EventCode 4720 + unknown usernames.

Enable base64 decoding plugins to auto-flag suspicious scripts.

Correlate with EDR and network logs to track payload delivery.

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T1-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T1-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T2-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T2-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T3-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T3-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T4-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T5-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T5-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T6-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T7-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T8-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T9-1.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T9-2.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T9-3.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T9-4.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T9-5.png)   

![image alt](https://github.com/andre5Jr/soc-analyst-SIEM-Investigating-With-Splunk/blob/c8fdb45e0548ffe9dc2a4010364f411ef18810e5/T9-6.png) 
