install_packages() {
	source ./ensure_bin.sh

	ensure_bin nginx mariadb-server php-fpm
	# php php-mysqli
	# https://make.wordpress.org/hosting/handbook/server-environment/#required-extensions
	echo "nginx, mariadb-server, php-fpm installed successfully."
	
	if ! wget -qO- https://wordpress.org/latest.tar.gz | tar -xz -C "$1" --strip-components=1; then
		echo "Error: Failed to download or extract WordPress." >&2
		exit 1
	fi
	
	echo "WordPress installed successfully in $1"
}
