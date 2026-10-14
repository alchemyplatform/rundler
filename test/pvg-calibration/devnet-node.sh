#!/usr/bin/env bash
# Runs a local geth + lighthouse node following glamsterdam-devnet-8 ("plataberget"), so the
# harness does not depend on the public RPC proxy. Lighthouse checkpoint-syncs and geth snap-syncs:
# only recent state is downloaded, old blocks are never executed.
#
#   ./devnet-node.sh start  <data-dir>   # first run downloads config and initialises geth
#   ./devnet-node.sh status
#   ./devnet-node.sh stop                # containers removed, data kept
#
# JSON-RPC (eth, net, web3, debug, txpool) is published on 127.0.0.1:8547 only; the beacon API
# on 127.0.0.1:5053. P2P ports are not published (outbound peering is enough).
set -euo pipefail

NETWORK=glamsterdam-devnet-8
CHAIN_ID=7091047534
CONFIG_BASE="https://raw.githubusercontent.com/ethpandaops/glamsterdam-devnets/master/network-configs/devnet-8/metadata"
CHECKPOINT_SYNC_URL="https://checkpoint-sync.${NETWORK}.ethpandaops.io"
GETH_IMAGE=ethpandaops/geth:master
LIGHTHOUSE_IMAGE=ethpandaops/lighthouse:unstable
DOCKER_NET=pvg-devnet
RPC_PORT=8547
BEACON_PORT=5053

start() {
    local dir=${1:?usage: $0 start <data-dir>}
    mkdir -p "$dir/config" "$dir/geth" "$dir/lighthouse"
    dir=$(cd "$dir" && pwd)

    if [ ! -f "$dir/config/genesis.json" ]; then
        for f in bootstrap_nodes.txt bootstrap_nodes.yaml config.yaml deposit_contract.txt \
            deposit_contract_block.txt deposit_contract_block_hash.txt enodes.txt genesis.json \
            genesis.ssz genesis_validators_root.txt; do
            curl -sSf -m 120 -o "$dir/config/$f" "$CONFIG_BASE/$f"
        done
        # Lighthouse testnet-dir names.
        cp "$dir/config/deposit_contract_block.txt" "$dir/config/deploy_block.txt"
        cp "$dir/config/bootstrap_nodes.yaml" "$dir/config/boot_enr.yaml"
    fi
    [ -f "$dir/config/jwt.hex" ] || { openssl rand -hex 32 > "$dir/config/jwt.hex"; chmod 600 "$dir/config/jwt.hex"; }
    if [ ! -d "$dir/geth/geth/chaindata" ]; then
        docker run --rm -v "$dir/geth:/data" -v "$dir/config:/config" "$GETH_IMAGE" \
            init --datadir /data --state.scheme path /config/genesis.json
    fi

    docker network inspect "$DOCKER_NET" >/dev/null 2>&1 || docker network create "$DOCKER_NET" >/dev/null

    docker run -d --name pvg-geth --network "$DOCKER_NET" -p "127.0.0.1:${RPC_PORT}:8545" \
        -v "$dir/geth:/data" -v "$dir/config:/config" "$GETH_IMAGE" \
        --datadir /data --networkid "$CHAIN_ID" --syncmode snap --state.scheme path \
        --http --http.addr 0.0.0.0 --http.port 8545 --http.vhosts '*' \
        --http.api eth,net,web3,debug,txpool \
        --authrpc.addr 0.0.0.0 --authrpc.port 8551 --authrpc.vhosts '*' \
        --authrpc.jwtsecret /config/jwt.hex \
        --bootnodes "$(grep -v '^\s*$' "$dir/config/enodes.txt" | paste -sd, -)" \
        --maxpeers 50 >/dev/null

    docker run -d --name pvg-lighthouse --network "$DOCKER_NET" -p "127.0.0.1:${BEACON_PORT}:5052" \
        -v "$dir/lighthouse:/data" -v "$dir/config:/config" "$LIGHTHOUSE_IMAGE" \
        lighthouse bn --testnet-dir /config --datadir /data \
        --execution-endpoint http://pvg-geth:8551 --execution-jwt /config/jwt.hex \
        --checkpoint-sync-url "$CHECKPOINT_SYNC_URL" \
        --boot-nodes "$(grep -v '^\s*$' "$dir/config/bootstrap_nodes.txt" | paste -sd, -)" \
        --http --http-address 0.0.0.0 --http-port 5052 --target-peers 30 >/dev/null

    echo "started; RPC http://127.0.0.1:${RPC_PORT} (wait for: $0 status -> synced)"
}

status() {
    local sync
    sync=$(curl -s -m 10 -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_syncing","params":[]}' \
        "http://127.0.0.1:${RPC_PORT}" || true)
    if echo "$sync" | grep -q '"result":false'; then
        echo "synced"
    else
        echo "syncing"
        docker logs pvg-geth 2>&1 | grep "Syncing:" | tail -2 || true
    fi
}

stop() {
    docker rm -f pvg-geth pvg-lighthouse >/dev/null 2>&1 || true
    echo "stopped (data kept)"
}

case "${1:-}" in
    start) shift; start "$@" ;;
    status) status ;;
    stop) stop ;;
    *) echo "usage: $0 {start <data-dir>|status|stop}" >&2; exit 2 ;;
esac
