#!/usr/bin/env bash
if [ "$EUID" -ne 0 ]; then
  echo "请使用 sudo 运行此脚本，或者以 root 用户身份运行。"
  exit 1
fi

set -e

apt-get update >/dev/null
apt-get install nginx -y >/dev/null
apt-get install mariadb-server -y
apt-get install php-fpm php php-mysqli -y

read -p "请输入网址: " DOMAIN
DIR="/var/www/$DOMAIN"
if [ -d "$DIR" ]; then
  rm -rf "$DIR"
fi

mkdir -p "$DIR"


