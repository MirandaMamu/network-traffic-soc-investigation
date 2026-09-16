# Network Traffic & SOC Investigation

## Incident Scenario

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

