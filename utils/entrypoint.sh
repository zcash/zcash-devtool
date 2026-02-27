#!/bin/sh

# Entrypoint for running zcash-devtool in Docker.
#
# The main script logic is at the bottom.
#
# ## Notes
#
# zcash-devtool is a stateless tool. Each command has some effect:
#   inspect
#     Intended to be run against "anything zcash" and provide information. For example,
#     an address, or a transaction.
#   wallet
#     Can create and inspect wallets, sync, send zec and so on. 

set -eo pipefail

# Main Script Logic
#
# 1. Print environment variables and config for debugging.
# 2. Tests if zcash-devtool runs, printing help.
# 3. Execs the CMD or custom command provided.

echo "INFO: Using the following environment variables:"
printenv

echo "Testing zcash-devtool to print version string:"
./zcash-devtool help

echo "now exec'ing $@ "
exec "$@"
