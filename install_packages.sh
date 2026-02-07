install_packages() {
	_ensure_apache_absent  # Ensure Apache is completely removed from the system to prevent conflicts with nginx
	
	source ./ensure_bin.sh
	# If PHP is installed first, Apache will be installed as a dependency.
	# Installing php-fpm first will install PHP automatically without Apache, avoiding conflicts with Nginx.
	ensure_bin nginx mariadb-server php-fpm php-mysql  # necessary for wordpress
	ensure_bin php-curl php-xml php-imagick php-mbstring php-zip php-gd php-intl  # suggest for wordpress
	# https://make.wordpress.org/hosting/handbook/server-environment/#required-extensions
	# nginx, mariadb-server, php-fpm auto-start and enable on boot by default
	# sudo systemctl enable service
	# sudo systemctl start service
	echo "nginx, mariadb-server, php-fpm and ohter php extensions installed successfully."

	# Download and extract the latest WordPress into /var/www/$DOMAIN
	if ! wget -qO- https://wordpress.org/latest.tar.gz | tar -xz -C "$1" --strip-components=1; then
		echo "Error: Failed to download or extract WordPress." >&2
		exit 1
	fi
	
	echo "WordPress installed successfully in $1"
}

_ensure_apache_absent() {
	if  command -v apache2 &>/dev/null; then
		apt purge -y apache2 
		# Using 'purge' instead of 'remove' ensures that configuration files and related data are deleted.
		# Specifically, it performs the following actions:
		# 1. Stops and disables the services:
		#       systemctl stop apache2
		#       systemctl disable apache2
		#       systemctl stop apache-htcacheclean
		#       systemctl disable apache-htcacheclean
		# 2. Deletes Apache configuration and default web files:
		#       /etc/apache2/ is removed
		#       /var/www/html/index.html is removed; if /var/www/ is empty after removal, the directory itself may be removed
		#       If /var/www/html contains other files, apt will report: "while removing apache2, directory '/var/www/html' not empty so not removed"
		# 3. Deletes Apache log files:
		#       /var/log/apache2/
		# 4. Removes systemd unit files and symlinks:
		#       /usr/lib/systemd/system/apache2.service
		#       /usr/lib/systemd/system/apache-htcacheclean.service
		#       /etc/systemd/system/multi-user.target.wants/apache*.service symlinks
		# This ensures Apache is fully uninstalled with no residual configuration, logs, or active service entries.
		# then `systemctl list-unit-files | grep apache` will be empty.
		
		apt autoremove -y --purge 
		# Automatically removes packages that were installed as dependencies but are no longer required.
		# Specifically, this includes apache2-bin, apache2-data, apache2-utils, and any other automatically installed packages no longer needed.
		# The '--purge' option ensures that any remaining configuration files for these packages are also deleted.
		
		systemctl daemon-reload  # refresh systemd to recognize changed/removed unit files such as /etc/systemd/system/multi-user.target.wants/apache*.service symlinks
	fi
}
