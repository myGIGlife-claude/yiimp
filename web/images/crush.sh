#!/bin/sh
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
find "$1" -name "*.png" | while IFS= read -r png
do
  echo "crushing $png"
  pngcrush -brute "$png" "$tmp" && cp -f "$tmp" "$png"
done
