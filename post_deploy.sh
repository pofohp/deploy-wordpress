post_deploy() {
	if [ "$DOMAIN" != "default" ]; then
		$HAVE_LOCAL_CONFIGURED_DNS || _remind_local_dns_resolution
		$HAVE_PUBLIC_IP && ! $HAVE_PUBLIC_CONFIGURED_DNS && _remind_publick_dns_resolution
	fi
	
	_remind_wp_init_protection
	_remind_import_self-signed_certificate
	$HAVE_PUBLIC_IP && _remind_apply_public_certificate
}

# post_deploy() {
#	:  # or use 'true'
# }
# If you don't put anything inside the function body, you may encounter an error in some cases, such as:
# -bash: syntax error near unexpected token `}'
# This can especially happen when executing a shell script.
# To avoid this, you can create a placeholder function that doesn't perform any actual operations. You can use one of the following two methods to prevent errors:
# `:' is an empty command in Bash that does nothing and always returns success (exit status 0). You can use it as a placeholder inside the function body.
# Alternatively, `true' is another commonly used empty command that always returns success (exit status 0). You can also use it inside the function body.

_remind_local_dns_resolution() {
	# primary_ip="192.168.1.1"
	# DOMAIN="www.example.com"
	
	echo "Reminder: To open PowerShell, press Win + X and select 'Terminal'. All commands mentioned below should be run in PowerShell."
	# echo "$(printf '-%.0s' {1..80})"
	# In some Bash or BusyBox environments, a format starting with '-' in printf may be misinterpreted as an option.
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"
	echo "Copy the following command and press Enter to add a DNS record at the bottom of the hosts file:"
	echo
	# Output a PowerShell command to add DNS, so the user can copy it
	cat <<EOF
\$add_dns = '$primary_ip $DOMAIN'
Start-Process powershell -Verb RunAs -ArgumentList @(
	"-NoProfile",
	"-ExecutionPolicy Bypass",
	"-Command",
	"\`\$add_dns='\$add_dns'; if ((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Raw).EndsWith('\`r\`n')) { Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value \`\$add_dns } else { Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value ('\`r\`n' + \`\$add_dns) };
	ipconfig /flushdns"
)

EOF
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"
	# For debugging, end with this below. Do not put a semicolon at the last command.
	# ipconfig /flushdns;
	# Read-Host 'Press Enter to exit'"
	
	echo "However, DNS resolution happens from top to bottom. If an old entry is above the one you just added, your new record might not work, causing issues. If you need to remove or edit the newly added entry, you can copy the following command to manually view and edit the file:"
	echo
	echo 'Start-Process notepad.exe -ArgumentList "C:\Windows\System32\drivers\etc\hosts" -Verb RunAs'
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"
	
	echo "You can also run the following command to check which DNS the domain currently points to:"
	echo
	echo "ping $DOMAIN"
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"
	
	echo "Tip: If you added a DNS record in the Cloudflare dashboard, it may take some time to propagate. You can manually change your DNS to 1.1.1.1 or 8.8.8.8, then run the following command to refresh the DNS cache:"
	echo
	echo 'ipconfig /flushdns'
	echo "$(printf '=%.0s' {1..80})"
}

_remind_publick_dns_resolution() {
	echo "You can add a dns resolution record accessing https://dash.cloudflare.com/ "
	echo "$DOMAIN → $primary_ip"
	echo "$(printf '=%.0s' {1..80})"
}

_remind_import_self-signed_certificate() {
	echo "accessing the link below to learn how to import a self-signed certificate when necessary: "
	echo
	echo "https://github.com/driverdrift/website-deploy/blob/main/README.md#import-a-self-signed-certificate-when-download-fails"
	echo "$(printf '=%.0s' {1..80})"
}

_remind_apply_public_certificate() {
	# considering certificate for ip or for domain.
	echo "accessing the link below to learn how to apply a public certificate when in production environment: "
	echo
	echo "https://github.com/driverdrift/website-deploy/"
	echo "$(printf '=%.0s' {1..80})"
}

# When copying the entire code of the function below,
# some parts of the code may be lost when pasting into a Linux terminal or Notepad++.
# This may be caused by data format issues, or by mouse malfunction during scrolling.
# In any case, do not overly trust copy-and-paste.
_remind_wp_init_protection() {
	if [ "$DOMAIN" = "default" ]; then
		local domain=$primary_ip
	else
		local domain=$DOMAIN
	fi

	# Inform the user that deployment is complete and WordPress init page is locked
	echo "1. Deployment complete! For security, the WordPress initialization page has been locked."
	echo "   Please run the following command to set your admin username and password:"
	echo
	# Show the command for creating Nginx access credentials
	echo 'read -p "Enter the Nginx access username you want to create: " u; htpasswd -c /etc/nginx/auth/wp_init.pass "$u"'
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"

	# Instructions after setting credentials
	echo "2. After setting up password, refresh the website page >>>>>> https://${domain} <<<<<< on a desktop web browser to continue WordPress installation."
	echo "   Do not use a mobile browser, as it may fail to load the login page."
	echo "$(printf '%s' "$(printf -- '-%.0s' {1..80})")"
	
	# Instructions for restoring site visibility after initialization
	echo "3. After wordpress initialization, you should run the following commands to restore site visibility by removing the protection files: "
	echo
	echo 'rm -rf "/etc/nginx/auth" && \
rm -f "/etc/nginx/conf.d/should_delete_after_wordpress_initialization.conf" && \
nginx -t &>/dev/null && systemctl reload nginx &>/dev/null || systemctl restart nginx &>/dev/null
[[ $? -eq 0 ]] && echo "Success: Your website is now visible." || echo -e "Error: Service failed to restart. The reason is: \n$(nginx -t 2>&1)"'
	echo "$(printf '=%.0s' {1..80})"
	################################################################################
	# [[ $? ]] && echo ok
	# This command cannot be used to determine whether the previous command succeeded.
	# The reason is that [[ $? ]] does NOT check “whether the previous command was successful”;
	# it checks whether the string represented by $? is non-empty.
	# In [[ STRING ]], the condition is true as long as STRING is non-empty.
	# Exit code semantics:
	#   false → $? = 1 or other number not zero
	#   true  → $? = 0
	# The string "0" is also non-empty, so it evaluates to true.
	# Therefore, [[ $? ]] will almost always be true.
	# The correct way is:
	# [[ $? -eq 0 ]]
	#
	# [[ true && true && false || false ]] || echo ok
	# Inside [[ ... ]]:
	#	true / false are NOT commands
	#	They are treated as ordinary strings
	#   && / || are logical operators internal to [[ ]]
	# This is equivalent to:
	# [[ "true" && "true" && "false" || "false" ]]
	# In [[ ]]:
	# - A non-empty string evaluates to true
	# Logical evaluation:
	# true && true && true || true  → true
	# Therefore, [[ true && true && false || false ]] will almost always be true.
	# see the link for the [[ ]] ussage: https://github.com/driverdrift/man-pages/blob/main/builtin/%5B%5B
	# see the link for the ussage of `test' builtin: https://github.com/driverdrift/man-pages/blob/main/builtin/test
	# As [[ ... ]]: [[ expression ]] Execute conditional command. Returns a status of 0 or 1 depending on the evaluation of the conditional
	# expression EXPRESSION.  Expressions are composed of the same primaries used
	# by the `test' builtin, and may be combined using the supported operators.
	# So we need to see the links of both `[[ ]]' and `test'.
	################################################################################
	#
	# [ true && true && false || false ] || echo ok
	#
	# This command will produce an error:
	# -bash: [: missing `]'
	#
	# Literal meaning: bash tried to execute the `[` command but could not find the required closing `]`.
	#
	# Key points about `[ ]`:
	# - `[` is not a shell syntax structure; it is a command (an alternative form of the `test` builtin).
	#   [ is either /usr/bin/[ or a bash built-in command.
	# - Its strict rule: the last argument must be a literal `]`.
	#   Usage example:
	#     [: [ arg... ] Evaluate conditional expression.
	#     This is a synonym for the "test" builtin, but the last argument must be a literal `]` to match the opening `[`.
	#     see the link for the [ ] ussage: https://github.com/driverdrift/man-pages/blob/main/builtin/%5B
	#     see the link for the ussage of `test' builtin: https://github.com/driverdrift/man-pages/blob/main/builtin/test
	#     we need to see the links of both `[ ]' and `test' as  `[ ]' is a synonym for the "test" builtin.
	#
	# - `[ ]` does NOT support `&&` or `||` as internal logical operators.
	#
	# How the shell parses `[ true && true && false || false ]`:
	# - It is equivalent to executing a command:
	#       /usr/bin/[ true && true && false || false ]
	#   (or the bash builtin `[`)
	# - Here `[` is the command name, `]` is the required last argument, and everything in between
	#   is treated as ordinary strings. `&&` and `||` are **not** interpreted as logical operators.
	#
	# - Only inside `[[ ... ]]` are `&&` and `||` recognized as logical operators.
	#
	# Shell parsing sequence:
	# - Shell first splits the command into tokens, then executes.
	#   This means the command effectively becomes:
	#       [ true &&     true       &&        false        || false ]  || echo a
	# - The first part `[ true` fails due to missing closing `]`, triggering:
	#       -bash: [: missing `]`
	# - Similar to `[[ ]]`, logical evaluation short-circuits:
	#   But here `[ true` fails, so the remaining tokens are skipped, 
	#   Then the execution jumps to `|| false ]' here. This command produces no output, 
	#   but if you run echo $?, the return value is 1. 
	#   Therefore, the subsequent echo a will be executed. and the exit status is 1,
	#   causing the `|| echo a' part to execute.
	#
	# Comparison: `[[]]` vs `[]`
	# - [[ true && false ]] → shell syntax, supports logical operators (though `false` inside is treated as non-empty string)
	# - [ true && false ] → command `[ true` gets executed; syntax is invalid, triggers error.
	#
	# Correct usage of `[ ]` (builtin `test` syntax):
	# - Exits with status 0 (true) or 1 (false) depending on the evaluation of EXPR.
	# - Can be used alone with `&&` / `||` outside, or in `if` statements (with optional `!` for negation).
	#
	# Examples:
	#   [ 1 -eq 0 ] || echo "not equal"
	#   if ! [ 1 -eq 0 ]; then echo "not equal"; fi
	#
	# Incorrect example (missing closing `]`):
	#   [ 1 -eq 1
	#
	# Historical note:
	# - `[` / `test` comes from early Unix; error messages are minimal and sometimes misleading.
	#
	# Common correct usages of `[ ]`:
	#
	# 1. Check previous command exit status:
	#   ls /tmp
	#   if [ $? -eq 0 ]; then
	#       echo ok
	#   fi
	#   - Only one test inside `[ ]`
	#   - Use test operators: -eq / -ne / -gt / -lt / etc.
	#   - Do not use `&&` or `||` inside `[ ]`; use `[[ ]]` for that.
	#
	# 2. Check if string is empty or non-empty:
	#   name="abc"
	#   [ -n "$name" ] && echo "not empty"
	#   [ -z "$name" ] && echo "empty"
	#
	# 3. Compare strings:
	#   a="foo"
	#   b="bar"
	#   [ "$a" = "$b" ] && echo same
	#   [ "$a" != "$b" ] && echo different
	#   - Must have spaces around `=` or `!=`.
	#
	# 4. Compare numbers:
	#   x=10
	#   [ "$x" -gt 5 ] && echo "x > 5"
	#   [ "$x" -le 20 ] && echo "x <= 20"
	#   - Valid operators: -eq -ne -gt -ge -lt -le
	#
	# 5. Check file existence:
	#   file=/etc/passwd
	#   [ -f "$file" ] && echo "regular file"
	#   [ -e "$file" ] && echo "exists"
	#   [ -d "$file" ] && echo "directory"
	#
	# 6. Multiple conditions (correct ways):
	#   [ "$a" = "foo" ] && [ "$b" = "bar" ] && echo ok
	#   # or (older style):
	#   [ "$a" = "foo" -a "$b" = "bar" ] && echo ok
	#
	# 7. Behavior of `[ false ]`:
	#   - Content is treated as a string → non-empty → exit status 0, echo $? will input 0.
	#   - Only `[ ]` with empty content → exit status 1, echo $? will input 1.
	################################################################################
	#
	# echo -e "Error: Service failed to restart. The reason is: \n" $(nginx -t 2>&1)
	# nginx output goes to stderr; without `2>&1`, it will appear before the prompt text
	# echo -e $(nginx -t 2>&1)
	# Without quotes: the shell performs word splitting on the command substitution result.
	# All whitespace characters (spaces, newlines, tabs) are treated as separators,
	# so newlines are converted into spaces.
	# As a result, everything is printed on a single line.
	# The `-e` option only interprets literal escape sequences like `\n`;
	# it does not restore newlines that were removed by the shell.
	# Therefore, the quoted form below is required.
	# echo -e "$(nginx -t 2>&1)"
	################################################################################
}
