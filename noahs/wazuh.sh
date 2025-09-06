#!/bin/bash

docker-desktop

open -a docker

git clone https://github.com/wazuh/wazuh-docker.git

cd wazuh-docker/single-node/

echo "services:
  generator:
    build:
      context: ../indexer-certs-creator
    volumes:
      - ./config/wazuh_indexer_ssl_certs/:/certificates/
      - ./config/certs.yml:/config/certs.yml
" > generate-indexer-certs.yml

sed -i '' 's/5\.0\.0/4.12.0/g' docker-compose.yml


docker compose -f generate-indexer-certs.yml build

docker compose -f generate-indexer-certs.yml run --rm generator

docker compose up -d
