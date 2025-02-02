# Install Wazuh

The recommended systems are: Red Hat Enterprise Linux 7, 8, 9; CentOS 7, 8; Amazon Linux 2; Ubuntu 16.04, 18.04, 20.04, 22.04. The current system does not match this list. Use -i|--ignore-check to skip this check.

## Wazuh Indexer

## Wazuh Server

## Wazuh Dashboard

### mitre technique filtering

```bash

rule.mitre.technique

```

- [ ] Vulnerability Scanning
- [ ] Password Guessing
- [ ] Stored Data Manipulation
- [ ] Modify Registry
- [ ] SSH
- [ ] Valid Accounts
- [ ] Brute Force
- [ ] Domain Accounts
- [ ] Pass The Hash
- [ ] Remote Desktop Protocol

### Windows Event ID filtering

```bash
data.win.system.eventID

```

[windows event code encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

### Active response

#### add to /var/ossec/etc/ossec.config

#### must have firewall enabled to drop

```bash
<ossec_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>180</timeout>
  </active-response>
</ossec_config>
```

### add sysmon alerts to wazuh agent and server

On windows Agent supply Sysmon64.exe with an .xml file
[download sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

try [swift on security sysmon config](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)

```cmd
Sysmon64.exe -accepteula -i detect_powershell.xml
```

The logs can be seen in event viewer under Applications and Service Logs / Microsoft / Sysmon / Operational

- add to ossec.conf

```bash
<localfile>
<location>Microsoft-Windows-Sysmon/Operational</location>
<log_format>eventchannel</log_format>
</localfile>
```

- then we must add a correponding rule for each in /var/ossec/rules/local_rules.xml

```bash
<group name="sysmon,">
 <rule id="255000" level="12">
 <if_group>sysmon_event1</if_group>
 <field name="sysmon.image">\\powershell.exe||\\.ps1||\\.ps2</field>
 <description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
 <group>sysmon_event1,powershell_execution,</group>
 </rule>
</group>
```

or

```bash
  <rule id="100001" level="1">
       <if_sid>100001</if_sid>
       <field name="Sysmon.EventID">1</field>
       <field name="Sysmon.CommandLine">*powershell.exe*</field>
       <description>PowerShell command line detected</description>
   </rule>
```

### monitoring Linux using auditd

```bash
sudo apt-get install auditd audispd-plugins
cd /etc/audit/rules.d/audit.rules

```

add to file to monitor all commands run as root

```bash
-a exit,always -F arch=64 -F euid=0 -S execve -k audit-wazuh-c
```

add to the server

```bash
<localfile>
    <location>/var/log/audit/audit.log</location>
    <log_format>audit</log_format>
</localfile>
```

### using api

```bash
TOKEN=$(curl -u <username>:<password> -k -X GET "https://WAZUH_MANAGEMENT_SERVER_IP:55000/security/user/authenticate?raw=true")
curl -k -X GET "https://10.10.17.180:55000/" -H "Authorization: Bearer $TOKEN"
```

### add vulnerability scanning

- add to /var/ossec/etc/shared/default/agent.conf
- uncomment operating systems you want to scan in /var/ossec/etc/ossec.conf

```bash
<wodle name="syscollector">
   <disabled>no</disabled>
   <interval>1h</interval>
   <os>yes</os>
   <packages>yes</packages>
   <hotfixes>yes</hotfixes>
</wodle>
```

### adding custom rules

#### sample asrep roasting

use gui to add to /etc/rules...local rules require a decoder, for this example you must enable kerberos auditing using auditpol or group policy

```bash
  <group name="windows,windows_security,">
    <rule id="100002" level="7">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4768$</field>
    <description>Potential AS-REP Roasting</description>
    </rule>
</group>
```

## detecting active directory attacks
“Replicating Directory Changes” and “Replicating Directory Changes All” 