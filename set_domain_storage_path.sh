set_domain_storage_path() {
	read -p "Please input domain you want to use（press enter to use ip address by default): " DOMAIN
	DOMAIN=${DOMAIN//[[:space:]]/}
	if [[ -z "$DOMAIN" ]]; then
		DIR="/var/www/default"
		echo "Use default website directory: $DIR"
	else
		if _is_valid_domain "$DOMAIN"; then
			DIR="/var/www/$DOMAIN"
			echo "Use custom domain directory: $DIR"
		else
			exit 1
		fi
	fi
}

_is_valid_domain() {
	local domain=$1
	# check domain length
	if (( ${#domain} > 255 )); then
		echo "your domain length is too long"
		return 1
	fi

	# check domain label
	if echo "$domain" | grep -Pq '^([a-z0-9-]{0,63}\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.(?=[a-z0-9-]*[a-z])[a-z0-9][a-z0-9-]{0,62}$'; then
		echo "Validated Successfully"
		return 0
	else
		echo "Invalid domain name"
		return 1
	fi
}

