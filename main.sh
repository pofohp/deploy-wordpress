#!/usr/bin/env bash

set -euo pipefail
trap 'rm -rf /tmp/website-deploy' EXIT
trap 'echo "operation is interrupted"; exit 130' INT

source ./set_domain_storage_path.sh
read DOMAIN DIR < <(set_domain_storage_path)

source ./install_packages.sh
install_packages "$DIR"

source ./edit_configuration.sh
edit_configuration "$DOMAIN" "$DIR"

# 使用链接避免php升级 sudo ln -sf /run/php/php8.3-fpm.sock /run/php/php-fpm.sock
# 默认站点目录 /var/www/wordpress 即可
