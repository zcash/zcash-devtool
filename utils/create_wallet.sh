#!/bin/sh

set -e

echo "Checking local docker image store to see if a zcash-devtool:latest image is present."
# Checks for empty string, discarding error messages.
if [ -z "$(docker images -q zcash-devtool:latest 2>/dev/null)" ]; then
  echo "There is no zcash-devtool:latest image listed by docker."
else
  echo "Creating wallet. Connecting via clearnet to zecrocks."
  docker run -it zcash-devtool:latest ./zcash-devtool wallet init --name "stagex_container_wallet" --identity ./age_id.txt --connection direct --network test -s zecrocks
fi
