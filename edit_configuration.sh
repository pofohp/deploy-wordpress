edit_configuration() {
	_mariadb_initial
	_edit_mariadb_configuration
	_edit_php_configuration
	_edit_wp_configuration "$2"  # DB_NAME / USER / PASS
	_generate_wp_salts
	_edit_wp_salts "$2"
}

_mariadb_initial() {
	# ================================================================
	# MariaDB Secure Initialization Simulation
	# This block of SQL commands simulates the effect of
	# `mariadb-secure-installation`:
	#   1. Switch root to unix_socket authentication
	#   2. Remove anonymous users
	#   3. Disallow remote root login
	#   4. Remove the test database
	#   5. Reload privilege tables
	#
	# WARNING: This is for initial security setup only.
	#          Do not run in production on a live system
	#          without understanding the effects.
	# ================================================================
	mariadb -e "
		ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;  # Switch to unix_socket authentication
		DELETE FROM mysql.user WHERE User='';  # Remove anonymous users
		DELETE FROM mysql.global_priv WHERE User='root' AND Host!='localhost';  # Disallow root login remotely
		DROP DATABASE IF EXISTS test;  # Remove test database and access to it
		FLUSH PRIVILEGES;  # Reload privilege tables now
		
		# debug
		/* SELECT User, Host, JSON_UNQUOTE(JSON_EXTRACT(priv, '$.authentication_string')) AS password,
		JSON_UNQUOTE(JSON_EXTRACT(priv, '$.plugin')) AS plugin FROM mysql.global_priv WHERE User='root'; */
		
		# SELECT User, Host FROM mysql.user;  # debug
		# SHOW DATABASES;  # debug
		"

	# ================= DEBUG SECTION =================
	# The following commands are for debugging/testing only.
	# They create an anonymous user, a remote root user, and a test database
	# to verify that the above removal/deletion commands work correctly.
	# DO NOT UNCOMMENT in production as these operations are unsafe.
	# =================================================
	# sudo mariadb -e "
	# 	CREATE USER IF NOT EXISTS ''@'localhost';  # Add anonymous users for debug
	# 	CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'TestPassword123!';  # Allow root login remotely for debug
	# 	CREATE DATABASE IF NOT EXISTS test;  # Add test database for debug
	# 	FLUSH PRIVILEGES;  # Reload privilege tables now
	# 	SELECT User, Host FROM mysql.user;  # view, not the real table, read-only, unlike mysql.global_priv which can be written.
	# 	SHOW DATABASES;
	# 	"
}

_edit_mariadb_configuration() {
	set +H  # disable history expansion
	
	# DOMAIN="www.google.com"
	DOMAIN_DB=${DOMAIN//./_}
	
	# database name should be no longer than 64
	DOMAIN_TRUNC_29=${DOMAIN_DB:0:29}
	DOMAIN_SHA12=$(printf "%s" "$DOMAIN" | sha256sum | cut -c1-12)
	DB_SALT=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9!@#%^_' | head -c 18)
	DB_NAME="wp-${DOMAIN_TRUNC_29}-${DOMAIN_SHA12}-${DB_SALT}"
	
	# user name should be no longer than 128
	DOMAIN_TRUNC_70=${DOMAIN_DB:0:70}
	DOMAIN_SHA32=$(printf "%s" "$DOMAIN" | sha256sum | cut -c1-32)
	USER_SALT=$(openssl rand -base64 40 | tr -dc 'A-Za-z0-9_' | head -c 20)
	DB_USER="wpu-${DOMAIN_TRUNC_70}-${DOMAIN_SHA32}-${USER_SALT}"
	
	DB_PASS=$(openssl rand -base64 24)
	DB_PASS=$(printf "%q" "$DB_PASS")
	
	DB_PREFIX="wp-${DOMAIN_TRUNC_29}-${DOMAIN_SHA12}-"
	for db in $(mariadb -sN -e "SHOW DATABASES LIKE '${DB_PREFIX}%';"); do
		echo "Dropping database $db"
		mariadb -e "DROP DATABASE IF EXISTS \`$db\`;"
	done
	
	USER_PREFIX="wpu-${DOMAIN_TRUNC_70}-${DOMAIN_SHA32}-"
	for user in $(mariadb -sN -e "SELECT User FROM mysql.user WHERE User LIKE '${USER_PREFIX}%';"); do
	    echo "Dropping user $user"
	    mariadb -e "DROP USER '$user'@'localhost';"
	done
	
	# echo "DB_NAME=${DB_NAME}" >> /root/wp-db-map.txt  # for debug
	# chmod 600 /root/wp-db-map.txt  # for debug
	
	mariadb -e "
		CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
		CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
		GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
		ALTER USER '${DB_USER}'@'localhost' PASSWORD EXPIRE NEVER;
		FLUSH PRIVILEGES;
		# SELECT User, Host, Db, Select_priv, Insert_priv FROM mysql.db;  # debug
		"
}

_edit_php_configuration() {
	PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
	PHP_INI="/etc/php/$PHP_VER/fpm/php.ini"

	awk '
	BEGIN {
		u = p = e = c = 0
	}
	
	{
		if ($0 ~ /^[[:space:]]*upload_max_filesize[[:space:]]*=/) {
			print "upload_max_filesize = 2000M"
			u = 1
			next
		}
		if ($0 ~ /^[[:space:]]*post_max_size[[:space:]]*=/) {
			print "post_max_size = 2006M"
			p = 1
			next
		}
		if ($0 ~ /^[[:space:]]*max_execution_time[[:space:]]*=/) {
			print "max_execution_time = 3000"
			e = 1
			next
		}
		if ($0 ~ /^[[:space:]]*;?[[:space:]]*cgi\.fix_pathinfo[[:space:]]*=/) {
			print "cgi.fix_pathinfo=0"
			c = 1
			next
		}
		print
	}
	
	END {
		if (!(u && p && e && c)) exit 1
	}
	' "$PHP_INI" > "$PHP_INI.tmp" && mv "$PHP_INI.tmp" "$PHP_INI" || {
		echo "ERROR: $PHP_INI does not match the expected template; at least one required setting was not found." >&2
		rm "$PHP_INI.tmp" >&2
		exit 1
	}
}

_edit_wp_configuration() {
	local web_dir="$1"  # such as "/var/www/www.example.com"
	local web_wp_config="${web_dir}/wp-config.php"
	cp "${web_dir}/wp-config-sample.php" "$web_wp_config"

	local domain_trunc_12=${DOMAIN_DB:0:12}
	local rand_suffix=$(openssl rand -base64 24 | tr -dc 'a-z0-9' | head -c 12)
	TABLE_PREFIX="${domain_trunc_12}_${rand_suffix}_"
	
	awk -v db_name="$DB_NAME" \
		-v db_user="$DB_USER" \
		-v db_pass="$DB_PASS" \
		-v db_prefix="$TABLE_PREFIX" '
	BEGIN {
		n = u = p = h = c = l = t = 0
	}

	# DB_NAME
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''DB_NAME'\''[[:space:]]*,/ {
		print "define( '\''DB_NAME'\'', '\''" db_name "'\'' );"
		n = 1
		next
	}

	# DB_USER
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''DB_USER'\''[[:space:]]*,/ {
		print "define( '\''DB_USER'\'', '\''" db_user "'\'' );"
		u = 1
		next
	}

	# DB_PASSWORD
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''DB_PASSWORD'\''[[:space:]]*,/ {
		print "define( '\''DB_PASSWORD'\'', '\''" db_pass "'\'' );"
		p = 1
		next
	}

	# DB_HOST
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''DB_HOST'\''[[:space:]]*,/ {
		print "define( '\''DB_HOST'\'', '\''localhost'\'' );"
		h = 1
		next
	}

	# DB_CHARSET
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''DB_CHARSET'\''[[:space:]]*,/ {
		print "define( '\''DB_CHARSET'\'', '\''utf8mb4'\'' );"
		c = 1
		next
	}

	# DB_COLLATE
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''DB_COLLATE'\''[[:space:]]*,/ {
		print "define( '\''DB_COLLATE'\'', '\''utf8mb4_unicode_ci'\'' );"
		l = 1
		next
	}

	# TABLE_PREFIX, no need \$ in print ""
	/^[[:space:]]*\$table_prefix[[:space:]]*=/ {
		print "$table_prefix = '\''" db_prefix "'\'';"
		t = 1
		next
	}

	{
		print
	}

	END {
		if (!(n && u && p && h && c && l && t)) exit 1
	}
	' "$web_wp_config" > "$web_wp_config.tmp" && \
	mv "$web_wp_config.tmp" "$web_wp_config" || {
		echo "ERROR: $web_wp_config does not match the expected WordPress template; database settings not fully found." >&2
		rm -f "$web_wp_config.tmp" >&2
		exit 1
	}
}

_generate_wp_salt() {
	# Available characters:
	# - Standard symbols commonly used in WordPress salts.
	# - Explicitly excluded: ' (single quote) and " (double quote) to prevent PHP syntax errors.
	# Use '--' to signal the end of options. This ensures that the leading '-'
	# inside the string isn't misread as a command-line flag (option) for 'tr'.
	# The hyphen '-' is placed at the start of the set so 'tr' treats it as a 
	# literal character instead of a range operator (like A-Z).
	while :; do
	s=$(tr -dc -- '-A-Za-z0-9!@#$%^&*()_=+[]{}|;:,.<>?/~`' \
		< /dev/urandom | head -c 64)
	
	[[ $s != *'/*'* ]] && { echo "$s"; break; }
	done
}

_generate_wp_salts() {
	AUTH_KEY=$(_generate_wp_salt)
	SECURE_AUTH_KEY=$(_generate_wp_salt)
	LOGGED_IN_KEY=$(_generate_wp_salt)
	NONCE_KEY=$(_generate_wp_salt)
	AUTH_SALT=$(_generate_wp_salt)
	SECURE_AUTH_SALT=$(_generate_wp_salt)
	LOGGED_IN_SALT=$(_generate_wp_salt)
	NONCE_SALT=$(_generate_wp_salt)
}

_edit_wp_salts() {
	local web_dir="$1"  # such as "/var/www/www.example.com"
	local web_wp_config="${web_dir}/wp-config.php"

	awk -v auth_key="$AUTH_KEY" \
		-v secure_auth_key="$SECURE_AUTH_KEY" \
		-v logged_in_key="$LOGGED_IN_KEY" \
		-v nonce_key="$NONCE_KEY" \
		-v auth_salt="$AUTH_SALT" \
		-v secure_auth_salt="$SECURE_AUTH_SALT" \
		-v logged_in_salt="$LOGGED_IN_SALT" \
		-v nonce_salt="$NONCE_SALT" '
	BEGIN {
		ak = sak = lk = nk = as = sas = ls = ns = 0
	}
	
	# AUTH_KEY
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''AUTH_KEY'\''[[:space:]]*,/ {
		print "define( '\''AUTH_KEY'\'',         '\''" auth_key "'\'' );"
		ak = 1; next
	}
	
	# SECURE_AUTH_KEY
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''SECURE_AUTH_KEY'\''[[:space:]]*,/ {
		print "define( '\''SECURE_AUTH_KEY'\'',  '\''" secure_auth_key "'\'' );"
		sak = 1; next
	}
	
	# LOGGED_IN_KEY
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''LOGGED_IN_KEY'\''[[:space:]]*,/ {
		print "define( '\''LOGGED_IN_KEY'\'',    '\''" logged_in_key "'\'' );"
		lk = 1; next
	}
	
	# NONCE_KEY
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''NONCE_KEY'\''[[:space:]]*,/ {
		print "define( '\''NONCE_KEY'\'',        '\''" nonce_key "'\'' );"
		nk = 1; next
	}
	
	# AUTH_SALT
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''AUTH_SALT'\''[[:space:]]*,/ {
		print "define( '\''AUTH_SALT'\'',        '\''" auth_salt "'\'' );"
		as = 1; next
	}
	
	# SECURE_AUTH_SALT
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''SECURE_AUTH_SALT'\''[[:space:]]*,/ {
		print "define( '\''SECURE_AUTH_SALT'\'', '\''" secure_auth_salt "'\'' );"
		sas = 1; next
	}
	
	# LOGGED_IN_SALT
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''LOGGED_IN_SALT'\''[[:space:]]*,/ {
		print "define( '\''LOGGED_IN_SALT'\'',   '\''" logged_in_salt "'\'' );"
		ls = 1; next
	}
	
	# NONCE_SALT
	/^[[:space:]]*define[[:space:]]*\([[:space:]]*'\''NONCE_SALT'\''[[:space:]]*,/ {
		print "define( '\''NONCE_SALT'\'',       '\''" nonce_salt "'\'' );"
		ns = 1; next
	}

	{
		print
	}

	END {
		if (!(ak && sak && lk && nk && as && sas && ls && ns)) exit 1
	}
	' "$web_wp_config" > "$web_wp_config.tmp" && \
	mv "$web_wp_config.tmp" "$web_wp_config" || {
		echo "ERROR: $web_wp_config does not contain all WordPress salt definitions." >&2
		rm -f "$web_wp_config.tmp"
		exit 1
	}
}
