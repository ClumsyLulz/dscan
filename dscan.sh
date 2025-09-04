#!/bin/bash
# dscan - Drupal Web Vulnerability Scanner 
# Version 1.0
# Author: Taylor Christian Newsome | ClumsyLulz

set -euo pipefail
IFS=$'\n\t'

# ------------------------------
# Banner
# ------------------------------
banner() {
    echo -e "\e[2;31m██████  ███████\e[0m  \e[2;34m██████\e[0m  \e[2;37m█████  ███    ██\e[0m"
    echo -e "\e[2;31m██   ██ ██ \e[0m     \e[2;34m██  \e[0m    \e[2;37m██   ██ ████   ██\e[0m"
    echo -e "\e[2;31m██   ██ ███████\e[0m  \e[2;34m██  \e[0m     \e[2;37m███████ ██ ██  ██\e[0m"
    echo -e "\e[2;31m██   ██      ██\e[0m  \e[2;34m██  \e[0m    \e[2;37m██   ██ ██  ██ ██\e[0m"
    echo -e "\e[2;31m██████  ███████\e[0m  \e[2;34m ██████\e[0m \e[2;37m██   ██ ██   ████\e[0m"
    echo -e "              Version 1.0 Made By Taylor Christian Newsome | ClumsyLulz"
    echo
}

# ------------------------------
# Usage / Help
# ------------------------------
usage() {
    banner
    echo "Usage: dscan [options] <target_url>"
    echo
    echo "Options:"
    echo "  -h, --help       Show this help message and exit"
    echo "  -t <threads>     Set maximum number of parallel threads (default: 50)"
    exit 0
}

# ------------------------------
# Default settings
# ------------------------------
MAX_THREADS=50

# ------------------------------
# Parse arguments
# ------------------------------
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -t) shift; MAX_THREADS="$1" ;;
        *) TARGET_URL="$1" ;;
    esac
    shift
done

if [ -z "${TARGET_URL-}" ]; then
    read -rp "Enter target URL (http://example.com): " TARGET_URL
fi

# ------------------------------
# Paths to check
# ------------------------------
paths_to_check=(
/admin /admin/config /admin/config/system /admin/config/people /admin/config/media
/admin/appearance /admin/modules /admin/content /admin/reports /admin/structure
/admin/structure/block /admin/structure/taxonomy /admin/structure/views
/admin/structure/menu /admin/structure/paragraphs /admin/structure/layout
/admin/structure/search /admin/structure/entity /admin/structure/migrate
/admin/structure/fields /admin/structure/users /admin/structure/custom-blocks
/admin/config/services /admin/config/media/image-style /admin/config/system/performance
/admin/config/system/smtp /admin/config/search/search-api
/admin/config/search/search-api/index /admin/config/search/search-api/server
/admin/config/development/logging /admin/config/development/cache
/admin/config/development/performance /admin/config/development/debugging
/admin/config/development/redis /admin/config/development/override
/admin/config/development/agentrace /admin/config/people/accounts
/admin/config/people/password-policy /admin/config/people/roles
/admin/config/people/permissions /admin/config/people/registration
/admin/config/people/session /admin/config/people/login
/admin/config/people/accounts/form /admin/config/people/roles/permissions
/admin/config/people/roles/create /admin/config/people/roles/update
/admin/config/people/roles/delete /admin/content/{content_type}
/admin/content/{content_type}/add /admin/content/{content_type}/edit/{node_id}
/admin/content/{content_type}/delete/{node_id} /node/add /node/add/article
/node/add/page /node/add/story /node/{nid}/edit /node/{nid}/delete /node/{nid}/view
/user/login /user/logout /user/register /user/password /user/{uid} /user/{uid}/edit
/user/{uid}/delete /user/{uid}/roles /user/{uid}/access /user/{uid}/content
/user/{uid}/settings /user/{uid}/session /user/{uid}/password /user/{uid}/profile
/user/{uid}/subscriptions /user/{uid}/posts /user/{uid}/comments /user/{uid}/notifications
/user/{uid}/messages /user/{uid}/inbox /user/{uid}/outbox /user/{uid}/activity
/core /core/install.php /core/misc /core/scripts /core/vendor /core/lib /core/themes
/core/assets /sites/default/files/ /sites/default/private/ /sites/default/settings.php
/sites/default/cron.php /rest/session/token /rest/views/{view_name}/page
/rest/views/{view_name}/json /rest/views/{view_name}/rss /rest/views/{view_name}/xml
/rest/{resource_name} /rest/{resource_name}/{id} /entity/{entity_type}/{id}
/robots.txt /crossdomain.xml /xmlrpc.php /update.php /about /help /donate
/terms-of-service /privacy-policy /404
)

# ------------------------------
# Security headers
# ------------------------------
security_headers=("X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection" "Content-Security-Policy" "Strict-Transport-Security")

# ------------------------------
# Drupal vulnerabilities
# ------------------------------
declare -A drupal_vulns=(
    ["Drupalgeddon2"]="/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    ["Drupalgeddon3"]="/user/password?name[%23post_render][]=system&name[%23markup]=phpinfo()&name[%23type]=markup"
)

# ------------------------------
# Functions
# ------------------------------
check_path() {
    local url="$1"
    local path="$2"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url/$path")
    if [[ "$status" == "200" || "$status" == "403" ]]; then
        echo "[FOUND] $url/$path (status $status)"
    fi
}

export -f check_path
export TARGET_URL

scan_security_headers() {
    local url="$1"
    local headers
    headers=$(curl -s -D - -o /dev/null "$url")
    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -iq "$header"; then
            echo "[SECURE] $header is present"
        else
            echo "[MISSING] $header"
        fi
    done
}

scan_drupal_vulns() {
    local url="$1"
    for name in "${!drupal_vulns[@]}"; do
        local path="${drupal_vulns[$name]}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url$path")
        if [[ "$status" == "200" ]]; then
            echo "[VULN] $name: $url$path"
        fi
    done
}

# ------------------------------
# Main Execution
# ------------------------------
banner
echo "[INFO] Scanning $TARGET_URL..."
echo "[*] Checking security headers..."
scan_security_headers "$TARGET_URL"

echo "[*] Enumerating paths..."
printf "%s\n" "${paths_to_check[@]}" | xargs -n1 -P "$MAX_THREADS" -I{} bash -c 'check_path "$0" "$1"' "$TARGET_URL" {}

echo "[*] Checking known Drupal vulnerabilities..."
scan_drupal_vulns "$TARGET_URL"
