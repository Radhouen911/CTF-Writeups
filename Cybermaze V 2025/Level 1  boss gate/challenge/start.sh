#!/bin/bash

set -e

nginx -g 'daemon off;' &
NGINX_PID=$!

uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1 &
UVICORN_PID=$!

trap "kill $NGINX_PID $UVICORN_PID 2>/dev/null; exit 0" SIGTERM SIGINT

wait
