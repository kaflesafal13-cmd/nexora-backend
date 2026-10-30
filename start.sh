#!/bin/sh
cd "$(dirname "$0")"
command -v node >/dev/null || { echo "Install Node.js 22.13+ from https://nodejs.org first."; exit 1; }
if [ ! -f .env ]; then
  printf "Admin username [safalkafle23]: "; read AU; AU=${AU:-safalkafle23}
  printf "Admin password (use a long one): "; read AP
  printf "PORT=3000\nADMIN_USERNAME=%s\nADMIN_PASSWORD=%s\nCOOKIE_SECURE=false\nTRUST_PROXY=false\n" "$AU" "$AP" > .env
fi
node --env-file-if-exists=.env server.js
