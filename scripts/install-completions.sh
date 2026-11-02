#!/usr/bin/env bash
# Install user-scoped dynamic shell completions for `zdev` (and optionally the
# full `zcash-devtool` CLI).
#
# The registration scripts are produced by clap_complete's dynamic completion
# engine (`COMPLETE=<shell>`), which completes subcommands recursively at any
# depth and offers options on an empty token. They only call back into `zdev`
# (or the binary) at completion time, so they do not go stale when the CLI
# changes.
#
#   scripts/install-completions.sh [--cli] [--uninstall]
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
data_home=${XDG_DATA_HOME:-$HOME/.local/share}

shells=(fish bash zsh powershell elvish)

# Standard user-scoped autoload location for command $2 in shell $1.
dest() {
    case $1 in
        fish) echo "$config_home/fish/completions/$2.fish" ;;
        bash) echo "$data_home/bash-completion/completions/$2" ;;
        zsh) echo "$data_home/zsh/site-functions/_$2" ;;
        powershell) echo "$config_home/powershell/completions/$2.ps1" ;;
        elvish) echo "$config_home/elvish/lib/$2.elv" ;;
    esac
}

names=(zdev)
uninstall=0
for arg in "$@"; do
    case $arg in
        --cli) names+=(zcash-devtool) ;;
        --uninstall) uninstall=1 ;;
        -h | --help)
            echo "Usage: scripts/install-completions.sh [--cli] [--uninstall]"
            echo "  --cli        also install completions for the full zcash-devtool CLI"
            echo "  --uninstall  remove installed completion files"
            exit 0
            ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [[ $uninstall -eq 1 ]]; then
    for name in zdev zcash-devtool; do
        for shell in "${shells[@]}"; do rm -f -- "$(dest "$shell" "$name")"; done
    done
    echo "Removed installed completions."
    exit 0
fi

bin=${DEVTOOL:-"$repo_root/target/release/zcash-devtool"}
[[ -x $bin ]] || bin=$(command -v zcash-devtool || true)

# Print the registration script for command $2 in shell $1.
generate() {
    if [[ $2 == zdev ]]; then
        COMPLETE=$1 "$repo_root/bin/zdev" || return
    else
        COMPLETE=$1 "$bin" || return
    fi
    # Autoloaded from fpath, the zsh script only registers itself on the first
    # Tab; complete right away too (as clap's static zsh scripts do).
    if [[ $1 == zsh ]]; then
        printf 'if [ "$funcstack[1]" = "_%s" ]; then _clap_dynamic_completer_%s "$@"; fi\n' "$2" "${2//-/_}"
    fi
}

for name in "${names[@]}"; do
    echo "Installing $name completions:"
    for shell in "${shells[@]}"; do
        file=$(dest "$shell" "$name")
        script=$(generate "$shell" "$name" 2>/dev/null) || {
            echo "error: could not generate completions; build zcash-devtool with --features tachyon first (see README.md)" >&2
            exit 1
        }
        mkdir -p -- "$(dirname -- "$file")"
        printf '%s\n' "$script" >"$file"
        printf '  %-10s %s\n' "$shell" "$file"
    done
done

cat <<EOF

One-time shell setup (fish needs none; bash needs bash-completion enabled):
  zsh:    in ~/.zshrc, before 'compinit':  fpath=("$data_home/zsh/site-functions" \$fpath)
  pwsh:   in \$PROFILE:                     . "$config_home/powershell/completions/zdev.ps1"
  elvish: in ~/.config/elvish/rc.elv:      use zdev

Completions call 'zdev' at completion time, so it must be on PATH
(direnv adds it inside the repo).
EOF
