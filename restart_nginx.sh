#!/bin/bash
set -ex

cp -v nginx.conf server.pem server.key /etc/nginx/
rsync -rv --delete javascript/ /etc/nginx/javascript

nginx -t
nginx -s reload
