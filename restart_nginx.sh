#!/bin/bash
set -ex

cp -v nginx.conf /etc/nginx/
if [[ -f server.pem ]]; then
    cp -v server.pem server.key /etc/nginx/
fi

rsync -rv --delete javascript/ /etc/nginx/javascript

nginx -t
nginx -s reload
