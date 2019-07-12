#!/bin/bash

set -e
(cd client && make clean && make && cd ..) || (echo "failed to build client" && exit 1)
(cd server && make clean && make && cd ..) || (echo "failed to build server" && exit 1)

echo "===================================="
echo "./run-server.sh port"
echo "./run-client.sh port"