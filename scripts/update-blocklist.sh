#!/bin/sh
# download the lists in config/blocklist-sources.txt and merge them into config/blocklist.txt, the default blocklist:
# keep only domains filter.c accepts, drop duplicates and domains whose parent domain is already listed,
# replace the old file only when every list downloads, then restart the router to load it
#
# usage: scripts/update-blocklist.sh [sources] [output]

set -eu
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
sources=${1:-$root/config/blocklist-sources.txt}
output=${2:-$root/config/blocklist.txt}
work=$(mktemp -d)
tmp=
trap 'rm -rf "$work"; [ -z "$tmp" ] || rm -f "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

# download URL $1 to file $2
fetch() {
	if command -v curl > /dev/null; then
		curl -fsSL --retry 2 --connect-timeout 20 --max-time 300 -o "$2" "$1"
	else
		wget -q --tries=3 --timeout=20 -O "$2" "$1"
	fi
}

# print the domains of hosts or domain list $1 lowercase without trailing dot, one per line, skip lines in other formats
# and names that are not public domains (localhost, local, broadcasthost, 0.0.0.0)
extract() {
	awk '
	function valid(d,    n, i, label) {
		if (length(d) > 253 || d !~ /[.]/ || d ~ /^[0-9.]+$/ || d ~ /[.](local|localdomain|localhost)$/)
			return 0
		n = split(d, label, "[.]")
		for (i = 1; i <= n; ++i)
			if (length(label[i]) > 63 || label[i] !~ /^[a-z0-9_-]+$/)
				return 0
		return 1
	}
	{
		gsub(/\r/, "")
		sub(/#.*/, "")
		first = 1
		if ($1 ~ /^[0-9.]+$/ || index($1, ":"))
			first = 2
		else if (NF > 1)
			next
		for (i = first; i <= NF; ++i) {
			d = tolower($i)
			sub(/[.]$/, "", d)
			if (valid(d))
				print d
		}
	}' "$1"
}

n=0
while read -r url _; do
	case $url in
	'' | '#'*) continue ;;
	esac
	n=$((n + 1))
	if ! fetch "$url" "$work/download"; then
		echo "cannot download $url" >&2
		exit 1
	fi
	extract "$work/download" | sort -u > "$work/$n.domains"
	count=$(wc -l < "$work/$n.domains")
	if [ "$count" -eq 0 ]; then
		echo "no domains in $url, it must be a hosts or domain list" >&2
		exit 1
	fi
	printf '%8d domains  %s\n' "$count" "$url"
	printf '#   %s (%d domains)\n' "$url" "$count" >> "$work/report"
done < "$sources"
if [ "$n" -eq 0 ]; then
	echo "no list in $sources" >&2
	exit 1
fi

# write the labels in reverse order separated by a space, which sorts before every label character, so a domain
# comes right before its subdomains, keep a domain only when it is not under the last kept one,
# then put the labels back in order
cat "$work"/*.domains |
	awk -F'[.]' '{ r = $NF; for (i = NF - 1; i; --i) r = r " " $i; print r }' |
	sort -u |
	awk 'index($0, kept " ") != 1 { kept = $0; print }' |
	awk '{ d = $NF; for (i = NF - 1; i; --i) d = d "." $i; print d }' |
	sort > "$work/merged"
total=$(wc -l < "$work/merged")

tmp=$(mktemp "$output.XXXXXX")
{
	echo "# made by scripts/update-blocklist.sh on $(date -u '+%Y-%m-%d %H:%M UTC') from:"
	cat "$work/report"
	echo "# $total domains, each also blocks its subdomains"
	cat "$work/merged"
} > "$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$output"
tmp=
echo "wrote $total domains to $output, restart the router to load them"
