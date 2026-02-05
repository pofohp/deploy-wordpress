set_domain_storage_path() {
	while true; do
		read -p "Please input domain you want to use（press enter to use ip address by default, press ctrl + c to exit): " DOMAIN
		DOMAIN=${DOMAIN//[[:space:]]/}
		
		if [[ -z "$DOMAIN" ]]; then
			DIR="/var/www/default"
			echo "Use default website directory: $DIR" >&2
			break
		else
			if _is_valid_domain "$DOMAIN"; then
				DIR="/var/www/$DOMAIN"
				echo "Use custom domain directory: $DIR" >&2
				break
			else
				echo "Please input a valid domain name..." >&2
				continue
			fi
		fi
	done

	if [[ -n "$DIR" && "$DIR" != "/" ]]; then
		if [[ -f "$DIR" ]]; then
			rm -f "$DIR"
		elif [[ -d "$DIR" ]]; then
			rm -rf "$DIR"
		fi
	fi

	mkdir -p "$DIR"
	test=test
	echo "${DOMAIN:-default}" "$DIR"
}

_is_valid_domain() {
	local domain=$1
	
	# check domain length
	if (( ${#domain} > 255 )); then
		echo "your domain length is too long" >&2
		return 1
	fi

	# check domain label
	if echo "$domain" | grep -Pq '^([a-z0-9-]{0,63}\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.(?=[a-z0-9-]*[a-z])[a-z0-9][a-z0-9-]{0,62}$'; then
		echo "Validated Successfully" >&2
		return 0
	else
		echo "Invalid domain name" >&2
		return 1
	fi
}
