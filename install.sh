#!/usr/bin/env bash

if [ "0" != "$UID" ]; then
  echo "This script should be run with root privileges."
else
  apt install -y python3 python3-pip python3-virtualenv python3-setuptools git dnsrecon nmap testssl.sh software-properties-common docker.io screen
fi
