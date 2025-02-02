#!/bin/bash
function check_command {
	if [ $? -ne 0 ]; then
		echo "error...exiting and removing wazuh-install directory"
  		exit 1
	else
		echo "...success..."
	fi
}

#check if user is root

if [ $(id -u) != 0 ]; then
    echo "script must be run as root..exiting"
        exit 1
fi


# extract archive
tar xf wazuh-offline.tar.gz

#check if dpkg is installed
if ! command -v dpkg >/dev/null 2>&1; then
        echo "system needs dpkg installed...exiting"
        rm -rf "$wazuh_directory"
        exit 1
fi

dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb

# create the proper directories add error checking
NODE_NAME="node-1"
mkdir /etc/wazuh-indexer/certs

mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem

mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem

mv wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/

mv wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/

cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

sed -i 's/network.host: "0.0.0.0"/network.host: "127.0.0.1"/g' /etc/wazuh-indexer/opensearch.yml
check_command

systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
curl -XGET https://localhost:9200 -u admin:admin -k
dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
systemctl status wazuh-manager
dpkg -i ./wazuh-offline/wazuh-packages/filebeat*.deb
cp ./wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/ &&\
cp ./wazuh-offline/wazuh-files/wazuh-template.json /etc/filebeat/ &&\
chmod go+r /etc/filebeat/wazuh-template.json
filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force
NODE_NAME='wazuh-1'
mkdir /etc/filebeat/certs
mv -n wazuh-certificates/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
curl -k -u admin:admin "https://localhost:9200/_template/wazuh?pretty&filter_path=wazuh.settings.index.number_of_shards"
dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb
NODE_NAME='dashboard'
mkdir /etc/wazuh-dashboard/certs
mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
#edit /etc/wazuh-dashboard/opensearch_dashboards.yml and change the server port to 7777
sed -i 's/server.port: 443/server.port: 7777/g' /etc/wazuh-dashboard/opensearch_dashboards.yml
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
systemctl status wazuh-dashboard
