# tested auditd rules linux

```bash
<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">

  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2
  -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

</group>
  <!-- group for auditd logging for linux hosts -->
<group name="audit,">
<!-- rule for alpine linux to monitor for /bin/busybox commands executed as root -->
    <rule id="100002" level="6">
       <if_sid>80792</if_sid>
       <field name="audit.exe">/bin/busybox</field>
       <field name="audit.euid">0</field>
       <field name="audit.egid">0</field>
       <description>Auditd: /bin/busybox commands being executed as root : $(audit.file.name) $(audit.execve.a0) $(audit.execve.a1)</description>
    <group>audit_command</group>
    </rule>
    <!-- monitor auditd for root commands, generic linux no busybox -->
    <!-- monitor sudo usage and output original uid -->
    <rule id="100003" level="6">
       <if_sid>80792</if_sid>
       <field name="audit.exe">/usr/bin/sudo</field>
       <description>Auditd: Sudo command detected used by user: $(audit.uid) command: $(audit.execve.a0) $(audit.execve.a1) $(audit.execve.a2) $(audit.execve.a3)</description>
    <group>audit_command</group>
    </rule>
    <rule id="100004" level="6">
       <if_sid>80792</if_sid>
       <field name="audit.euid">0</field>
       <field name="audit.egid">0</field>
       <description>Auditd: commands run as root $(audit.file.name) $(audit.execve.a0) $(audit.execve.a1) $(audit.execve.a2) $(audit.execve.a3)</description>
       <group>audit_command</group>
    </rule>
</group>
```
