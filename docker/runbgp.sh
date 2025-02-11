#!/bin/bash

# Run BGP daemon
echo "Starting BGP daemon..."
/app/gobgpd -f /app/gobgpd.yml 