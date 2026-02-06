# Check and display the status of common web services
for service in apache2 nginx php8.2-fpm mariadb; do
  echo "===== $service status ====="
  sudo systemctl status $service --no-pager
  echo
done



# Notes:
php-fpm       PHP FastCGI Process Manager, used with Nginx
php-mysql     MySQL/MariaDB support, required for WordPress database connection
php-curl      CURL HTTP requests support, used by plugins and themes
php-gd        Image processing library, needed for WordPress image editing/resizing
php-mbstring  Multibyte string support (for Chinese, Japanese, etc.)
php-xml       XML parsing, used for RSS and plugin features
php-xmlrpc    XML-RPC protocol support, for remote publishing and plugins like Jetpack
php-soap      SOAP protocol support, used by advanced plugins and services
php-intl      Internationalization support, localization and string comparison
php-zip       Zip file support, needed for plugin installs and backups
php-bz2       Bzip2 compression support, needed for plugin installs and backups
php-cli       PHP command line interface
php-cgi       PHP CGI mode support, usually not needed with Nginx + FPM

# Stop Apache service
sudo systemctl stop apache2
# Disable Apache from starting on boot
sudo systemctl disable apache2
# Remove Apache packages
sudo apt purge apache2 apache2-utils apache2-bin apache2.2-common -y
# Remove unused dependencies
sudo apt autoremove -y
# Optional: Remove leftover config files
sudo rm -rf /etc/apache2
# Check that Apache is fully removed and Nginx is running
sudo systemctl status nginx
