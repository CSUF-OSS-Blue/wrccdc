#!/bin/bash

wazuh_install_script_path="./wazuh-install.sh"
function check_command {
	if [ $? -ne 0 ]; then
		echo "error...exiting"
		exit 1
	else
		echo "...success..."
	fi
}
node_ip=$1
#check if root
if [ "$(whoami)" != "root" ]; then
	echo "script must be run as root...exiting"
	exit 1

fi
#check if ip address is entered as argument and is valid
if [ $# -ne 1 ]; then
	echo "[!] correct syntax is: ./wazuh_deploy.sh <ip address of this host>"
	exit 1
else
	ip a | grep "$node_ip" >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "$node_ip not found on local interfaces..exiting"
		exit 1

	fi
fi
#if wazuh-install directory exists prompt user to delete
if [ -d ./wazuh-install ]; then
	read -p "wazuh-install directory exists is it ok to delete(y/n)?" choice
	if [ "$choice" == 'y' ] || [ "$choice" == 'Y' ]; then
		rm -rf wazuh-install
		echo "...deleted"
	else
		echo "ok...exiting..."
		exit 1
	fi
fi
#create and change to wazuh-install
mkdir wazuh-install
cd wazuh-install || exit

#indexer installation
echo "downloading wazuh-install.sh"
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
check_command
echo "downloading config.yml"
curl -sO https://packages.wazuh.com/4.7/config.yml
check_command
echo "setting indexer node ip in config.yml"
sed -i "s/<indexer-node-ip>/${node_ip}/g" config.yml
check_command
echo "setting manager node ip in config.yml"
sed -i "s/<wazuh-manager-ip>/${node_ip}/g" config.yml
check_command
echo "setting dashboard node ip in config.yml"
sed -i "s/<dashboard-node-ip>/${node_ip}/g" config.yml
check_command
echo "setting wazuh-install.sh to executable"
chmod +x ./wazuh-install.sh
check_command
# run wazuh-install.sh --generate-config-files
echo "setting wazuh-install.sh --generate-config-files"
bash $wazuh_install_script_path --generate-config-files
check_command
# wazuh indexer nodes installation
echo "setting wazuh-install.sh --wazuh-indexer node 1"
bash $wazuh_install_script_path --wazuh-indexer node-1
check_command
echo "setting wazuh-install.sh --start-cluster"
bash $wazuh_install_script_path --start-cluster
check_command
echo "getting username and password"
username_password=$(tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1)
check_command
echo "wazuh username and password:"
echo "$username_password"
pw=$(echo "$username_password" | awk '{print $4}' | tr -d "'")
check_command
echo "testing cluster..."
curl -k -u admin:"$pw" https://"$node_ip":9200
check_command
echo "checking node..."
curl -k -u admin:"$pw" https://"$node_ip":9200/_cat/nodes?v
check_command

# server cluster installation
echo "installing wazuh server..."
bash $wazuh_install_script_path --wazuh-server wazuh-1
check_command

# wazuh dashboard installation
echo "installing wazuh dashboard on port $node_ip:9000..."
bash $wazuh_install_script_path --wazuh-dashboard dashboard -p 9000
check_command

echo "don't forget to import root.ca.pem to your browser!"
echo "bye!"
