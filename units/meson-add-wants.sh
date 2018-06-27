#!/bin/sh
set -eu

unitdir="$1"
target="$2"
unit="$3"

case "$target" in
        */?*) # a path, but not just a slash at the end
                dir="${DESTDIR:-}${target}"
                ;;
        *)
                dir="${DESTDIR:-}${unitdir}/${target}"
                ;;
esac

unitpath="${DESTDIR:-}${unitdir}/${unit}"

case "$target" in
        */)
                mkdir -p -m 0755 "$dir"
                ;;
        *)
                mkdir -p -m 0755 "$(basename "$dir")"
                ;;
esac

if [ -d "$dir" ]; then
        rm -f "$dir/$unit"
        lnr "$unitpath" "$dir/$unit"
else
        lnr "$unitpath" "$dir"
fi
