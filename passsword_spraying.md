Threat Hunt — Password Spraying
Hypothesis
An external threat actor is attempting to gain initial access to the environment by performing a password spraying attack
. Unlike a traditional brute-force attack that targets one account with many passwords, this actor is testing a single common password against a high volume of unique usernames to stay below account lockout thresholds and evade simple detection
.
Data Source
Windows Security Event Logs: Event ID 4625 (An account failed to log on)
.
Kerberos Telemetry: Event ID 4771 (Kerberos pre-authentication failed), which provides a domain-controller-side view of failed attempts
.

Sysmon: Event ID 3 (Network connection) to correlate failed logons with specific source IP addresses
.


KQL (Microsoft Sentinel/Defender)
// Hunting for one IP hitting multiple accounts
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedAccountCount = dcount(TargetUserName) by RemoteIP, bin(TimeGenerated, 1h)
| where FailedAccountCount > 10
| project TimeGenerated, RemoteIP, FailedAccountCount
| sort by FailedAccountCount desc
Logic: This query identifies a single source IP address attempting to log into more than 10 unique accounts within a one-hour window
.


SPL (Splunk)
index=auth EventCode=4625 earliest=-24h 
| stats count(TargetUserName) as total_failures, dc(TargetUserName) as unique_accounts by src_ip 
| where unique_accounts > 5
| sort - unique_accounts
Logic: This "Pro-Level" query aggregates failed logons by source IP and filters for those hitting more than 5 unique accounts, a classic signature of password spraying
.
Findings
During the hunt, a source IP (192.168.1.45) was identified generating a massive spray of Event ID 4625 across 50+ unique usernames within 15 minutes
. The hunt becomes critical if a single Event ID 4624 (Successful Logon) from that same IP follows the failures, indicating a successful breach
.
False Positives
Misconfigured Service Accounts: A service account (e.g., svc_backup) with an expired password attempting to sync across multiple servers
.
Legacy Applications: Older software using NTLM where Kerberos is expected, causing repeated authentication noise
.
Authorized Pentesting: Internal security teams running vulnerability or credential audits
.
MITRE ATT&CK
Tactic: Credential Access (TA0006)
.
Technique: Brute Force: Password Spraying (T1110.003)
.
Detection Improvement
Alert Tuning: Create a SIEM alert that triggers when a single source IP generates failed logons for >X accounts in Y minutes
.
Security Controls: Enforce Multi-Factor Authentication (MFA) and implement rate limiting at the network edge to block IPs after a set number of failures
.
Risk-Based Alerting: Correlate failed logons with Geolocation data to flag attempts originating from countries where the company does not conduct business
