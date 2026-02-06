install_packages() {
	source ./ensure_bin.sh

	ensure_bin nginx mariadb-server php-fpm php-mysql  # necessary
	ensure_bin php-curl php-xml php-imagick php-mbstring php-zip php-gd php-intl  # suggest
	# nginx, mariadb-server, php-fpm auto-start and enable on boot by default
	# sudo systemctl enable service
	# sudo systemctl start service
	
	# php php-mysqli
	# https://make.wordpress.org/hosting/handbook/server-environment/#required-extensions

	# sudo apt install  php    php-xmlrpc php-soap  \
#  php-bz2 php-cli php-cgi  -y
	
	echo "nginx, mariadb-server, php-fpm installed successfully."

	# Download and extract the latest WordPress into /var/www/$DOMAIN
	if ! wget -qO- https://wordpress.org/latest.tar.gz | tar -xz -C "$1" --strip-components=1; then
		echo "Error: Failed to download or extract WordPress." >&2
		exit 1
	fi
	
	echo "WordPress installed successfully in $1"
}
