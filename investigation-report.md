# SOC Investigation Report

> **Note:** This is a simulated SOC investigation created for cybersecurity learning and portfolio demonstration.

## Executive Summary

This investigation examined suspicious PowerShell activity involving a Base64-encoded command on a Windows endpoint.

The investigation included PowerShell command analysis, DNS activity review, network-traffic review, indicator identification, and incident assessment.

The available evidence identified suspicious activity requiring further investigation, but did not conclusively establish endpoint compromise or malicious external communication.

The investigation demonstrates a structured SOC workflow of alert analysis, evidence collection, correlation, assessment, and recommended response actions.


# Network Traffic & SOC Investigation

## 1. Incident Scenario

A workstation on the internal network has generated unusual network traffic.

You are the junior SOC analyst assigned to investigate the activity and determine whether it represents a potential security incident.

## Investigation Data

| Time | Source IP | Destination IP | Protocol | Destination Port | Activity |
|---|---|---|---|---:|---|
| 09:01 | 192.168.1.25 | 8.8.8.8 | UDP | 53 | DNS query |
| 09:03 | 192.168.1.25 | 93.184.216.34 | TCP | 80 | HTTP connection |
| 09:07 | 192.168.1.25 | 185.199.108.153 | TCP | 443 | HTTPS connection |
| 09:12 | 192.168.1.25 | 10.10.10.20 | TCP | 445 | SMB connection |
| 09:15 | 192.168.1.25 | 203.0.113.50 | TCP | 4444 | Unexpected connection |

## Analyst Questions

1. What is the source IP address?
2. Which traffic appears normal?
3. Which connection appears suspicious?
4. What is unusual about port 4444?
5. What indicators of compromise (IOCs) can be identified?
6. What should the SOC analyst investigate next?

## Initial Assessment

**Status:** Under investigation

**Severity:** To be determined

**Potential IOC:** 203.0.113.50:4444

## Next Steps

Further investigation is required before determining whether the workstation has been compromised.

 ## Investigation Findings

### 1. Source and Destination

The workstation `192.168.1.25` was communicating with the external destination `203.0.113.50`.

### 2. Suspicious Port

The connection used TCP port `4444`.

Port 4444 is not automatically malicious, but it is commonly associated with remote-control and penetration-testing activity. Because the workstation was making an unexpected external connection on this port, it required further investigation.

### 3. Process Investigation

The connection was associated with `powershell.exe`.

PowerShell is a legitimate Windows administration tool, but it can also be abused to execute commands and scripts.

### 4. Encoded PowerShell Command

The PowerShell command used the `-enc` parameter, indicating that the command was encoded.

I used CyberChef's **From Base64** operation to decode the command.

The decoded command contained:

`IEX -NoProfile -WindowStyle Hidden -Command`

### 5. Suspicious Behaviour

The use of `-WindowStyle Hidden` is suspicious because it allows PowerShell to execute without displaying the PowerShell window to the user.

### 6. Analyst Assessment

The activity is suspicious because the workstation is communicating with an external IP address over an unusual port while PowerShell is executing an encoded command with the window hidden.

The evidence does not by itself prove that the workstation is compromised. Further investigation would be required.

## Next Investigation Steps

The next step would be to correlate the available evidence with additional security telemetry.

Recommended checks include:

- Review authentication logs for unusual or failed login activity.
- Check DNS queries associated with the suspicious activity.
- Review network connections and identify the destination IP address and port.
- Determine whether the workstation communicated with other suspicious hosts.
- Check endpoint security alerts for related activity.
- Review the user's recent activity for signs of phishing or credential compromise.

These checks would help determine whether the observed activity is an isolated event or part of a broader security incident.

## Evidence Gap

The available evidence records a DNS query from the workstation to 8.8.8.8 over port 53 at 09:01, but the queried domain name is not available.

Because the domain name and DNS response are missing, the DNS event cannot currently be correlated with the later connection to 203.0.113.50:4444.

Additional DNS logs or packet capture would be required to determine what domain was queried and what IP address was returned.

## PowerShell Analysis

The workstation executed PowerShell.exe with the following arguments:

- `-NoProfile`
- `-WindowStyle Hidden`
- `-enc` (EncodedCommand)

The use of an encoded PowerShell command and a hidden PowerShell window is suspicious because these techniques can reduce visibility during command execution. However, these indicators alone do not prove malicious activity.

The PowerShell execution occurred in the context of a network connection from the workstation to `203.0.113.50:4444`. The combination of the PowerShell execution characteristics and the network connection increases the need for further investigation.

Further evidence, such as the decoded command, process creation logs, endpoint telemetry, and related network activity, would be required to determine the purpose of the PowerShell execution.

## Timeline Analysis

The available evidence shows two relevant events involving the same workstation, `192.168.1.25`.

At 09:01, the workstation generated a DNS query to `8.8.8.8` over port 53. The queried domain and DNS response are not available in the evidence.

At 09:15, the workstation was associated with `PowerShell.exe` executing with `-NoProfile`, `-WindowStyle Hidden`, and `-enc`. A network connection to `203.0.113.50` over port 4444 was also observed.

The 14-minute gap between the DNS event and the later PowerShell/network activity is noteworthy, but the available evidence does not establish that the two events are directly related.

Additional logs would be required to establish the sequence and relationship between the events.

## Alert Triage and Priority

The activity should be treated as suspicious and investigated further.

The combination of a hidden PowerShell execution, an encoded command, and a network connection to an external destination on port 4444 increases the investigative priority of the alert.

However, the available evidence does not confirm that the workstation has been compromised. The encoded PowerShell command was decoded during the investigation using CyberChef. The decoded value was IEX -NoProfile -WindowStyle HidenCommand. There is currently no DNS domain or response, malware identification, persistence evidence, or confirmed malicious payload in the available data.

Recommended priority: Medium-High.

The priority should be reassessed if additional evidence confirms malicious execution, persistence, credential theft, lateral movement, or other indicators of compromise.

## Final Analyst Assessment

The investigation identified multiple suspicious indicators involving workstation `192.168.1.25`.

The evidence shows PowerShell execution using `-NoProfile`, `-WindowStyle Hidden`, and an encoded command. The encoded command was decoded during the investigation using CyberChef. Network activity to external destination `203.0.113.50:4444` was also observed.

The available evidence is sufficient to justify escalation for further investigation, but it is not sufficient to confirm that the workstation was compromised.

Recommended next actions are to collect additional endpoint telemetry, review the PowerShell process tree, obtain the relevant DNS query and response, investigate the network connection, and determine whether any persistence, credential theft, lateral movement, or other malicious activity occurred.

**Assessment: Suspicious activity requiring further investigation and escalation.**


## 2. DNS Investigation

### Objective

Determine whether the suspicious PowerShell activity was associated with any DNS queries or external domains.

### Investigation

DNS activity can help identify systems contacted by a potentially compromised host. During the investigation, DNS queries should be reviewed for suspicious domains, unusual hostnames, or connections that may support the PowerShell activity identified earlier.

### Findings

No confirmed malicious domain has been identified at this stage.

Further analysis of network traffic and DNS logs is required to determine whether the PowerShell activity resulted in external communication.

## 3. Network Traffic Investigation

### Objective

Determine whether the endpoint established any network connections associated with the suspicious PowerShell activity.

### Investigation

Network traffic should be reviewed for:

- Source and destination IP addresses
- Destination ports
- Protocols used
- External connections
- Unusual or unexpected communication
- Connections occurring around the time of the PowerShell activity

### Findings

No confirmed malicious network connection has been identified at this stage.

The available evidence does not currently establish that the suspicious PowerShell activity resulted in communication with a malicious external host.

Further network analysis would be required to confirm whether any outbound connections were made.

## 4. PowerShell Analysis and Indicators of Compromise

### Objective

Analyse the suspicious PowerShell command and identify any indicators that could support further investigation.

### Analysis

The PowerShell command was Base64 encoded, which can be used to obscure command content and make analysis more difficult.

The encoded command was decoded during the investigation. The decoded content included PowerShell execution parameters and behaviour that warranted further investigation.

### Indicators of Compromise

The following indicators were identified from the available evidence:

- PowerShell execution
- Base64-encoded command
- Suspicious command-line activity
- Hidden PowerShell execution parameters

### Assessment

The use of an encoded PowerShell command is a notable security indicator. However, the available evidence alone is not sufficient to confirm that the endpoint was compromised.

Additional telemetry, including process creation events, network connections, and endpoint logs, should be correlated before making a final determination.

## 5. Incident Timeline

| Stage | Activity | Significance |
|---|---|---|
| 1 | Suspicious PowerShell activity detected | Initial security indicator |
| 2 | PowerShell command identified as Base64 encoded | Obfuscation technique identified |
| 3 | Encoded command decoded for analysis | Command behaviour could be reviewed |
| 4 | DNS activity reviewed | No confirmed malicious domain identified |
| 5 | Network activity reviewed | No confirmed malicious external connection identified |
| 6 | Evidence correlated | Further telemetry required for confirmation |

### Timeline Assessment

The investigation began with suspicious PowerShell activity and progressed through command analysis, DNS review, and network-traffic investigation.

Based on the available evidence, suspicious activity was identified, but there is insufficient evidence to conclusively determine that the endpoint was compromised.

## 6. Incident Assessment

### Severity

**Medium — Suspicious Activity Requiring Further Investigation**

### Rationale

The investigation identified suspicious PowerShell execution involving an encoded command. This behaviour warrants investigation because PowerShell can be used to execute commands and scripts on Windows systems.

However, the available evidence does not confirm successful compromise, malicious network communication, or data exfiltration.

### Recommended Actions

1. Continue monitoring the affected endpoint.
2. Review additional Windows and PowerShell event logs.
3. Correlate process creation events with network activity.
4. Investigate any associated IP addresses or domains.
5. Check for persistence mechanisms or additional suspicious processes.
6. Escalate the incident if additional evidence confirms malicious activity.

## 7. Containment and Remediation

### Containment

If additional evidence confirms malicious activity, the affected endpoint should be isolated from the network to prevent potential lateral movement or further communication with external systems.

The suspicious PowerShell activity should also be investigated and terminated where appropriate.

### Remediation

Recommended remediation actions include:

- Review and remove any confirmed malicious files or scripts.
- Investigate and remove persistence mechanisms if identified.
- Reset affected credentials if compromise is confirmed.
- Apply relevant security patches and updates.
- Review PowerShell logging and security controls.
- Verify that endpoint protection is functioning correctly.

### Lessons Learned

This investigation demonstrated the importance of correlating multiple sources of evidence rather than relying on a single alert.

Key indicators included encoded PowerShell activity, DNS activity, and potential network communication.

The investigation also demonstrated the value of combining endpoint and network analysis when investigating suspicious activity.

