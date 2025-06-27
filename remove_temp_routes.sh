#!/bin/sh
# remove_temp_routes.sh - Deletes all temporary routes with expiration
#
# This script scans the routing tables using `netstat` and deletes any
# routes that have an expiration timer. Designed for FreeBSD and requires
# root privileges.

# shellcheck disable=SC2016

# Iterate over routing tables and remove entries that have a numeric
# expiration time in the last column.

set -e

clean_table() {
    proto="$1"
    netstat -rnW -f "$proto" \
        | awk 'NR>4 && $NF ~ /^[0-9]+$/ {print $1}' \
        | while read -r dst; do
            route -n delete "$dst" >/dev/null 2>&1
        done
}

clean_table inet
clean_table inet6

