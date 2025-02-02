#!/usr/bin/python

# script to add fim to ossec.conf via ssh

import paramiko
import termcolor
import maskpass
import argparse
from datetime import datetime

# command= "echo 'test2' >> /tmp/test/config.txt"
parser = argparse.ArgumentParser()
parser.add_argument("ip")
parser.add_argument("directory")
args = parser.parse_args()
ip_address = args.ip
dir_loc = args.directory


username = input(termcolor.colored("[?]", "green") + " Enter username: ")
print(termcolor.colored("[?] ", "green"), end="")
password = maskpass.askpass(prompt="Password: ", mask="#")


with open("fim.txt", "w") as f:
    f.write("<ossec_config>\n")
    f.write("<syscheck>\n")
    f.write("<frequency>300</frequency>\n")
    f.write("<directories>" + dir_loc + "</directories>\n")
    f.write("</syscheck>\n")
    f.write("</ossec_config>\n")
    f.close()

client = paramiko.client.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(ip_address, username=username, password=password)
except paramiko.AuthenticationException:
    print(termcolor.colored("[!]", "red") + " Authentication error try again.")
    exit(1)
sftp = client.open_sftp()
print(
    termcolor.colored("[-] ", "green")
    + "Adding "
    + dir_loc
    + " to the list of monitored directories for "
    + ip_address
)
now = datetime.now()
backup_fn = "./ossec.conf." + now.strftime("%m-%d-%H-%M")
sftp.get("/var/ossec/etc/ossec.conf", backup_fn)
with open("fim.txt", "r") as f:
    text = f.read()

    with sftp.file("/var/ossec/etc/ossec.conf", "a") as remote_file:
        remote_file.write(text)

sftp.close()
_stdin, _stdout, _stderr = client.exec_command("cp /var/ossec/etc/ossec.conf ")
_stdin, _stdout, _stderr = client.exec_command("systemctl restart wazuh-agent")
print(termcolor.colored("[-]", "green") + " Restarting Wazuh agent")
if _stderr.read().decode():
    print(termcolor.colored("[!]") + " An error occoured: ")
    print(_stderr.read().decode())
else:
    print(termcolor.colored("[-]", "green") + " Restart successful")
print(_stdout.read().decode())
client.close()
