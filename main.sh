#!/usr/bin/env bash

set -euo pipefail
trap 'rm -rf /tmp/website-deploy; declare -F cleanup &>/dev/null && cleanup' EXIT
# Ensures that if the script exits unexpectedly, the cleanup function is only called if it has been defined.
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
