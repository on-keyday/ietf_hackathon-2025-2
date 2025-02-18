#!/bin/sh

SERVER="2001:db8:0:2::5"
# ping infinity
ping $SERVER &

# sending tcp message to server
while true; do
    echo "Hello, World!" | nc $SERVER 8080
    sleep 1
done

