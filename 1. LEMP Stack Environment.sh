# Check and display the status of common web services
for service in apache2 nginx php8.2-fpm mariadb; do
  echo "===== $service status ====="
  sudo systemctl status $service --no-pager
  echo
done

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
