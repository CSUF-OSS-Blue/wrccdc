# Wazuh Offline Installation

[official documentation](https://documentation.wazuh.com/current/deployment-options/offline-installation.html)

I stored these files on my kali vm under /home/kali/Documents/wazuh-offline/deb and /rpm

## on host with internet access

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
chmod 744 wazuh-install.sh
./wazuh-install.sh -dw <deb|rpm>
```

```bash

curl -sO https://packages.wazuh.com/4.7/config.yml

```

## config.yml

all-in-one deployment, replace "\<indexer-node-ip\>", "<wazuh-manager-ip>", and "\<dashboard-node-ip\>" with 127.0.0.1.

```bash

 sed -i 's/<indexer-node-ip>/127.0.0.1/g' config.yml
 sed -i 's/<wazuh-manager-ip>/127.0.0.1/g' config.yml
 sed -i 's/<dashboard-node-ip>/127.0.0.1/g' config.yml
```

```bash
curl -sO https://packages.wazuh.com/4.6/wazuh-certs-tool.sh
chmod 744 wazuh-certs-tool.sh
./wazuh-certs-tool.sh --all
```

- transfer the offline archive and certificate folder with scp to server host, use scp -r to transfer the certicicate folder

## on server host

- uncompress the archive

```bash
tar xf wazuh-offline.tar.gz
```

- install the indexer

### rpm

```bash
rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-indexer*.rpm
```

### deb

```bash
dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb
```

replace $NODE_NAME with node-1

- make sure the certs tool creates all the required certs and that they are named correctly!!!

```bash

mkdir /etc/wazuh-indexer/certs
mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
mv wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/
mv wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```

- edit /etc/wazuh-indexer/opensearch.yml
- change network.host to 127.0.0.1

- check indexer node address, leave master note alone for single host deployment

- plugin security node is ok as is for single node deployment
- then.....drumroll....

```bash
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
```

## start the cluster ....another drumroll...

```bash
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

## check the indexer via port 9200

```bash
curl -XGET https://localhost:9200 -u admin:admin -k
```

- output should look like this:

```bash
{
  "name" : "node-1",
  "cluster_name" : "wazuh-cluster",
  "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
  "version" : {
    "number" : "7.10.2",
    "build_type" : "rpm",
    "build_hash" : "db90a415ff2fd428b4f7b3f800a51dc229287cb4",
    "build_date" : "2023-06-03T06:24:25.112415503Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

## installing the wazuh manager

### rpm

```bash
rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-manager*.rpm
```

### deb

```bash
dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb
```

### start and enable the wazuh manager

```bash
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
```

## install filebeat

### rpm

```bash
rpm -ivh ./wazuh-offline/wazuh-packages/filebeat*.rpm
```

### deb

```bash
dpkg -i ./wazuh-offline/wazuh-packages/filebeat*.deb
```

### move the configuration files

```bash
cp ./wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/ &&\
cp ./wazuh-offline/wazuh-files/wazuh-template.json /etc/filebeat/ &&\
chmod go+r /etc/filebeat/wazuh-template.json
```

### edit /etc/filebeat/wazuh-template.json

- change index.number_of_shards to "1"

```bash
{
  ...
  "settings": {
    ...
    "index.number_of_shards": "1",
    ...
  },
  ...
}
```

### check /etc/filebeat/filebeat.yml

- make sure your localhost is set for hosts

- create filebeat keystore to store credentials

```bash
filebeat keystore create
```

- add the default passwords to the keystore

```bash
echo admin | filebeat keystore add username --stdin --force

echo admin | filebeat keystore add password --stdin --force
```

- install the wazuh module for filebeat

```bash
tar -xzf ./wazuh-offline/wazuh-files/wazuh-filebeat-0.2.tar.gz -C /usr/share/filebeat/module
```

- enter a NODE_NAME="wazuh-1" to fill in the following commands

```bash
mkdir /etc/filebeat/certs

mv -n wazuh-certificates/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem

mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem

cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/

chmod 500 /etc/filebeat/certs

chmod 400 /etc/filebeat/certs/*

chown -R root:root /etc/filebeat/certs
```

- enable and start

```bash
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
```

### test file beat

```bash
filebeat test output
```

elasticsearch: https://127.0.0.1:9200...
parse url... OK
connection...
parse host... OK
dns lookup... OK
addresses: 127.0.0.1
dial up... OK
TLS...
security: server's certificate chain verification is enabled
handshake... OK
TLS version: TLSv1.3
dial up... OK
talk to server... OK
version: 7.10.2

- check if number of "shards" are correct

```bash
curl -k -u admin:admin "https://localhost:9200/_template/wazuh?pretty&filter_path=wazuh.settings.index.number_of_shards"
```

## Install the dashboard

### rpm

```bash
rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-dashboard*.rpm
```

### deb

```bash
dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb
```

NODE_NAME='dashboard'

```bash
mkdir /etc/wazuh-dashboard/certs
mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

```

### edit /etc/wazuh-dashboard/opensearch_dashboards.yml

set server host to 0.0.0.0
set server.port to a good port default 443
set opensearch.hosts to https://localhost:9200
set opensearch.ssl.verificationMode certificate

```
server.host: 0.0.0.0
server.port: 443
opensearch.hosts: https://localhost:9200
opensearch.ssl.verificationMode: certificate
```

- start and enable the services

```bash
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
```

# deploy agents

[wazuh packages](https://documentation.wazuh.com/current/installation-guide/packages-list.html)

use python server, scp or other method to transfer to hosts
