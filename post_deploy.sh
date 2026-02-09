post_deploy(){
}

_remind_dns_resolution() {
	real_ip="192.168.1.1"
	DOMAIN="www.example.com"
	
	echo
	echo "Reminder: To open PowerShell, press Win + X and select 'Terminal'. All commands mentioned below should be run in PowerShell."
	# echo "$(printf '-%.0s' {1..80})"
	# In some Bash or BusyBox environments, a format starting with '-' in printf may be misinterpreted as an option.
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"
	echo "Copy the following command and press Enter to add a DNS record at the bottom of the hosts file:"
	echo
	# Output a PowerShell command to add DNS, so the user can copy it
	cat <<EOF
\$add_dns = '$real_ip $DOMAIN'

Start-Process powershell -Verb RunAs -ArgumentList @(
	"-NoProfile",
	"-ExecutionPolicy Bypass",
	"-Command",
	"\`\$add_dns='\$add_dns'; if ((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Raw).EndsWith('\`r\`n')) { Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value \`\$add_dns } else { Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value ('\`r\`n' + \`\$add_dns) };
	ipconfig /flushdns"
)

EOF
	echo "$(printf '=%.0s' {1..80})"
	# For debugging, end with this below. Do not put a semicolon at the last command.
	# ipconfig /flushdns;
	# Read-Host 'Press Enter to exit'"
	
	echo "However, DNS resolution happens from top to bottom. If an old entry is above the one you just added, your new record might not work, causing issues. If you need to remove or edit the newly added entry, you can copy the following command to manually view and edit the file:"
	echo
	echo 'Start-Process notepad.exe -ArgumentList "C:\Windows\System32\drivers\etc\hosts" -Verb RunAs'
	echo "$(printf '=%.0s' {1..80})"
	
	echo "You can also run the following command to check which DNS the domain currently points to:"
	echo
	echo "ping $DOMAIN"
	echo "$(printf '=%.0s' {1..80})"
	
	echo "Tip: If you added a DNS record in the Cloudflare dashboard, it may take some time to propagate. You can manually change your DNS to 1.1.1.1 or 8.8.8.8, then run the following command to refresh the DNS cache:"
	echo
	echo 'ipconfig /flushdns'
	echo "$(printf '=%.0s' {1..80})"
	echo
}
