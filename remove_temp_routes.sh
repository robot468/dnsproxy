#!/bin/sh
# remove_temp_routes.sh - Deletes all temporary routes with expiration
#
# This script scans the routing tables and deletes any routes with an
# expiration timer. Works on FreeBSD and Linux; root privileges required.

# shellcheck disable=SC2016

# Iterate over routing tables and remove entries that have a numeric
# expiration time in the last column.

set -e

if [ "$(uname -s)" = "Linux" ]; then
    ip -4 route show table main | awk '/expires/ {print $1}' | while read -r dst; do
        ip route del "$dst" >/dev/null 2>&1
    done
    ip -6 route show table main | awk '/expires/ {print $1}' | while read -r dst; do
        ip -6 route del "$dst" >/dev/null 2>&1
    done
else
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
fi

