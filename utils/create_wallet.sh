#!/bin/sh

set -e

echo "Checking local docker image store to see if a zcash-devtool:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q zcash-devtool:latest 2>/dev/null)" ]; then
  echo "There is no zcash-devtool:latest image listed by docker."
else
  echo "Creating wallet if there is none, then printing wallet's orchard u address."
  docker run zcash-devtool:latest ./zcash-devtool wallet help
fi
