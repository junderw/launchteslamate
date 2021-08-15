#!/bin/bash
set -euo pipefail

# Just in case things need time to start up
sleep 10

MAIN_DOMAIN=[HOSTNAME]
MY_GLOBAL_IP=[IP]
SSL_EXPIRE_EMAIL=[EMAIL]
NGINX_BASIC_AUTH=[NGINXPASSWORD]
TESLAMATE_TZ=[TZ]
REPOSITORY=[REPOSITORY]
BRANCH=[BRANCH]

UBUNTU_HOME=/home/ubuntu

echo "Starting script..."

# Make sure we can get the lets encrypt cert properly
MAIN_DOMAIN_IP=$(dig @resolver4.opendns.com $MAIN_DOMAIN +short)
if [[ "$MY_GLOBAL_IP" != "$MAIN_DOMAIN_IP" ]]; then
  echo "Please set Main site domain to $MAIN_DOMAIN this server Global IP: $MY_GLOBAL_IP" 1>&2
  exit 1
fi

# create 1 GB of swap memory
dd if=/dev/zero of=/swapfile1 bs=1024 count=1048576
chmod 600 /swapfile1
mkswap /swapfile1
swapon /swapfile1

# persist swap memory
echo "/swapfile1 swap swap defaults 0 0" | tee -a /etc/fstab

mkdir -p "$UBUNTU_HOME/teslamate/config"

echo "SSL_EXPIRE_EMAIL=${SSL_EXPIRE_EMAIL:-tslamt$(date +%s)@tslamt$(date +%s)dmn.com}
TESLAMATE_MAIN_DOMAIN=$MAIN_DOMAIN
CONFIG_BASE=$UBUNTU_HOME/teslamate/config
TESLAMATE_TZ=$TESLAMATE_TZ
INTERNAL_PASSWORD=$(openssl rand -hex 20)
" > "$UBUNTU_HOME/teslamate/.env"

chown -R ubuntu:ubuntu "$UBUNTU_HOME/teslamate"

mkdir -p $UBUNTU_HOME/teslamate/config/teslamate-grafana-data
mkdir -p $UBUNTU_HOME/teslamate/config/nginx/htpasswd

# Needed to fix issues with permissions
chown 472:root $UBUNTU_HOME/teslamate/config/teslamate-grafana-data

apt update
apt upgrade -y
apt install apache2-utils -y

htpasswd -c -b $UBUNTU_HOME/teslamate/config/nginx/htpasswd/$MAIN_DOMAIN admin $NGINX_BASIC_AUTH

# Grab docker-compose from gist
curl -fsSL ${REPOSITORY/github.com/raw.githubusercontent.com}/${BRANCH}/docker-compose.yml -o "$UBUNTU_HOME/teslamate/docker-compose.yml"

# Install docker
curl -fsSL https://get.docker.com -o "$UBUNTU_HOME/get-docker.sh"
sh "$UBUNTU_HOME/get-docker.sh"

# Install docker-compose
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version

cd "$UBUNTU_HOME/teslamate"

docker-compose up -d

[ -x "$(command -v /etc/init.d/sshd)" ] && nohup /etc/init.d/sshd restart &
[ -x "$(command -v /etc/init.d/ssh)" ] && nohup /etc/init.d/ssh restart &
