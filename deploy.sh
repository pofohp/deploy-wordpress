#!/usr/bin/env bash
if [ "$EUID" -ne 0 ]; then
  echo "Run with sudo or as root."
  exit 1
fi

set -e

is_valid_domain() {
    local domain=$1
    if [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]; then
        return 0
    else
        return 1
    fi
}

read -p "请输入网址（回车使用ip）: " DOMAIN
DOMAIN=${DOMAIN// /}
if [[ -z "$DOMAIN" ]]; then
    DIR="/var/www/default"
    echo "使用默认目录：$DIR"
else
    # 验证域名
    if is_valid_domain "$DOMAIN"; then
        DIR="/var/www/$DOMAIN"
        echo "使用域名目录：$DIR"
    else
        echo "输入不合法域名，脚本退出"
        exit 1
    fi
fi

if [ -d "$DIR" ]; then
  rm -rf "$DIR"
fi

mkdir -p "$DIR"

apt-get update >/dev/null
wget -qO- https://wordpress.org/latest.tar.gz | tar -xz -C "$DIR" --strip-components=1

apt-get install nginx -y >/dev/null
apt-get install mariadb-server -y
# https://make.wordpress.org/hosting/handbook/server-environment/#required-extensions
apt-get install php-fpm php php-mysqli -y

# 使用链接避免php升级 sudo ln -sf /run/php/php8.3-fpm.sock /run/php/php-fpm.sock
# 默认站点目录 /var/www/wordpress 即可
