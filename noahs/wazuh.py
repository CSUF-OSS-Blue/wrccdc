import subprocess as sp
import os



sp.run(['git', 'clone', 'https://github.com/wazuh/wazuh-docker.git'])

yaml_text = """
services:
  generator:
    build:
      context: ../indexer-certs-creator
    volumes:
      - ./config/wazuh_indexer_ssl_certs/:/certificates/
      - ./config/certs.yml:/config/certs.yml
"""

with open("wazuh-docker/single-node/generate-indexer-certs.yml", "w") as f:
    f.write(yaml_text)


file_path = "wazuh-docker/single-node/docker-compose.yml"

with open (file_path, "r") as f:
    content = f.read()

content = content.replace("5.0.0", "4.12.0")

with open(file_path, "w") as f:
    f.write(content)

os.chdir('wazuh-docker/single-node/')

sp.run(['docker', 'compose', '-f', 'generate-indexer-certs.yml', 'build'])

sp.run(['docker','compose','-f','generate-indexer-certs.yml','run','--rm','generator'])

sp.run(['docker', 'compose', 'up', '-d'])
