#!/usr/bin/env bash

set -euo pipefail
trap 'declare -F cleanup &>/dev/null && cleanup; rm -rf /tmp/website-deploy' EXIT
# Previously, the trap was:
# trap 'rm -rf /tmp/website-deploy; declare -F cleanup &>/dev/null && cleanup' EXIT
# In that version, the cleanup function could run to the end, but UFW rules and
# the token file were not cleared. /tmp/website-deploy is the script's download
# and working directory, so I initially thought deleting the script first caused
# the variables to be lost.
# Now it seems the real issue was using `$()` to call functions, which confines
# variables like UFW_RULE_ADDED to a subshell.
# The script is already loaded into memory when running, so deleting the script
# file before calling cleanup does not affect variable access.
# However, to avoid unpredictable issues, it's safer to run all functions first
# and only remove the script files at the very end.
# Besides: Ensures that if the script exits unexpectedly, the cleanup function 
# is only called if it has been defined.
# Checks functions only. Stable behavior with clear semantics.
# Better suited for scripts.

# type cleanup &>/dev/null && cleanup
# `type` may match an alias, builtin, or external command.
# In strict scripts, this is not precise enough for function checks.

trap 'echo "operation is interrupted"; exit 130' INT

if [[ ! "${1-}" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
	echo "Warning: Continuing will delete existing website files and databases on the system."
	read -p "Do you want to proceed? [y/N]: " confirm
	if [[ ! "$confirm" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
		echo "Operation cancelled."
		exit 1
	fi
fi

source ./set_domain_storage_path.sh
read DOMAIN DIR < <(set_domain_storage_path)

source ./install_packages.sh
install_packages "$DIR"

source ./edit_configuration.sh
edit_configuration "$DOMAIN" "$DIR"

echo "Install website successfully."

source ./post_deploy.sh
post_deploy
