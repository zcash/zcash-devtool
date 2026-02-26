#!/bin/sh

set -e

DIR="$( cd "$( dirname "$0" )" && pwd )"
REPO_ROOT="$(git rev-parse --show-toplevel)"
PLATFORM="linux/amd64"
OCI_OUTPUT="$REPO_ROOT/build/oci"
DOCKERFILE="$REPO_ROOT/Dockerfile"
NAME=zcash-devtool

export DOCKER_BUILDKIT=1
export SOURCE_DATE_EPOCH=1

echo $DOCKERFILE
mkdir -p $OCI_OUTPUT

# Build runtime image for docker run
echo "Building runtime image..."
docker build -f "$DOCKERFILE" "$REPO_ROOT" \
	--platform "$PLATFORM" \
	--target runtime \
	--output type=oci,rewrite-timestamp=true,force-compression=true,dest=$OCI_OUTPUT/zcash-devtool.tar,name=zcash-devtool \
	"$@"

# Extract from export stage
echo "Extracting binaries..."
docker build -f "$DOCKERFILE" "$REPO_ROOT" --quiet \
	--platform "$PLATFORM" \
	--target export \
	--output type=local,dest="$REPO_ROOT/build" \
	"$@"
