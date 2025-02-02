# Agents

## linux

### arch linux

- Installing agent on arch

```bash
pacman --noconfirm -Syu curl gcc make sudo wget expect gnupg perl-base perl fakeroot python brotli automake autoconf libtool gawk libsigsegv nodejs base-devel inetutils cmake
curl -Ls https://github.com/wazuh/wazuh/archive/v4.7.1.tar.gz | tar zx
cd wazuh-4.7.1
./install.sh
systemctl start wazuh-agent
#### auditd
```

- note : when auditd is installed before the agent it will automatically monitor /var/log/audit/audit.log
- if not...

```bash
# add to /var/ossec/etc/ossec.conf on agent
<localfile>
    <location>/var/log/audit/audit.log</location>
    <log_format>audit</log_format>
</localfile
```

```bash
 3.7- Setting the configuration to analyze the following logs:

    -- /var/log/audit/audit.log
    -- /var/ossec/logs/active-responses.log
```

[installing wazuh from sources](https://documentation.wazuh.com/current/deployment-options/wazuh-from-sources/wazuh-agent/index.html)

- enable vulnerabliltiy scanning

```bash
# enter in /var/ossec/etc/ossec.conf on agent
<wodle name="syscollector">
   <disabled>no</disabled>
   <interval>1h</interval>
   <os>yes</os>
   <packages>yes</packages>
   <hotfixes>yes</hotfixes>
</wodle>
```

- change vulnerability scanning to on on agent /var/etc/ossec/ossec.conf

```bash
<!-- Arch OS vulnerabilities -->
    <provider name="arch">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>
# interval can be hours or minutes
```

- enable file integrity monitoring and who data

```bash
# in /var/ossec/etc/ossec.conf on agent
   <syscheck>
   <directories check_all="yes" whodata="yes">/etc</directories>
   </syscheck>
# testing to see if this can be added to default for /etc/ /bin directories

```

- set frequency to 300 for competition
- use auditcheck to list rules and load rules file

```bash
# list
auditctl -l
# load
auditctl -R /etc/rules/rules.d/audit.rules
# add to /etc/rules/rules.d/audit.rules for monitoring the root execution syscall
-a exit,always -F arch=b64 -F euid=0 -S execve -k  audit-wazuh-c
-a exit,always -F arch=b32 -F euid=0 -S execve -k  audit-wazuh-c
```

### alpine linux

- install auditd

```bash
apk update
apk add audit
# might need to start and enable manually
rc-update add auditd default # add to default run level
rc-service --list
# start
rc-service auditd start
#check run levels
rc-status
#check version
 apk info audit
```

- Wazuh agent installation from repository

```bash
# remember the command is doas instead of sudo usually
wget -O /etc/apk/keys/alpine-devel@wazuh.com-633d7457.rsa.pub https://packages.wazuh.com/key/alpine-devel%40wazuh.com-633d7457.rsa.pub
echo "https://packages.wazuh.com/4.x/alpine/v3.12/main" >> /etc/apk/repositories
apk update
apk add wazuh-agent
export WAZUH_MANAGER="10.0.0.2" && sed -i "s|MANAGER_IP|$WAZUH_MANAGER|g" /var/ossec/etc/ossec.conf
# then you can add the agent name under the <client><enrollment><agent_name>AGENT_NAME</agent_name></enrollment></client>...also <groups>
/var/ossec/bin/wazuh-control start
```

- vulnerability detection for alpine is not supported
- add audit rules for sudo execution

```bash
# list
auditctl -l
# load
auditctl -R /etc/rules/rules.d/audit.rules
# add to /etc/rules/rules.d/audit.rules for monitoring the root execution syscall
-a exit,always -F arch=b64 -F euid=0 -S execve -k  audit-wazuh-c
-a exit,always -F arch=b32 -F euid=0 -S execve -k  audit-wazuh-c
# below are some good auditctl rules that filter out processes that run root commands
-a always,exit -F arch=b32 -S execve -F auid=0 -F egid!=994 -F auid!=-1 -F key=audit-wazuh-c
-a always,exit -F arch=b64 -S execve -F auid=0 -F egid!=994 -F auid!=-1 -F key=audit-wazuh-c
```

- check and make sure that audit is set for a log type in ossec.conf on the agent just like above

# Agentless monitoring (files and diff commands)

- use /var/ossec/agentless/register_host.sh script to add a host to monitor

```bash
# with pub key authentication...check /var/ossec/logs/ossec.log to see if it worked!
/var/ossec/agentless/register_host.sh add user@test.com NOPASS
# with password, remember to do history -c after its in clear text
/var/ossec/agentless/register_host.sh add user@test.com test_password
# list hosts
/var/ossec/agentless/register_host.sh list
# install expect on wazuh server
apt install -y expect
# add to ossec.conf on server...I couldn' get this to trigger
<agentless>
  <type>ssh_integrity_check_bsd</type>
  <frequency>20000</frequency>
  <host>user@test.com</host>
  <state>periodic</state>
  <arguments>/bin /var/</arguments>
</agentless>
# the diff command however did work
<agentless>
  <type>ssh_generic_diff</type>
  <frequency>20000</frequency>
  <host>user@test.com</host>
  <state>periodic_diff</state>
  <arguments>ls -la /etc</arguments>
</agentless>
```

- go to Discover and enter agentless.host:\* to see events and add the fields to save a search for later

# blocking ips
