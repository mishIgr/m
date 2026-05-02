#!/bin/bash
set -e

DEPLOY_DIR="$HOME/.local/share/m/deploy"
BUILD_TYPE="release"

for arg in "$@"; do
    case "$arg" in
        --debug) BUILD_TYPE="debug" ;;
    esac
done

if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --release -p m_server -p m_client
else
    cargo build -p m_server -p m_client
fi

CLIENT_BIN="$HOME/.local/bin"
CLIENT_CONFIG="$HOME/.config/m"
CLIENT_DATA="$HOME/.local/share/m"

mkdir -p "$DEPLOY_DIR" "$CLIENT_BIN" "$CLIENT_CONFIG" "$CLIENT_DATA/client-logs"

cp "target/$BUILD_TYPE/m_server" "$DEPLOY_DIR/m_server"
cp config/server.template.toml "$DEPLOY_DIR/m_server.template.toml"

cp "target/$BUILD_TYPE/m_client" "$CLIENT_BIN/m_client"

if [ ! -f "$CLIENT_CONFIG/client.toml" ]; then
    cp config/client.toml "$CLIENT_CONFIG/client.toml"
fi

echo "Successful installation"
