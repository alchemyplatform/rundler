#!/usr/bin/env bash
# End-to-end check of reservoir mode against a running rundler on Sepolia (Glamsterdam).
#
# Sends a user operation that deploys a large contract (default 24 kB, ~38M of EIP-8037 state
# gas) through rundler's RPC, the way a wallet would:
#   eth_estimateUserOperationGas -> eth_sendUserOperation -> eth_getUserOperationReceipt
# and then checks the bundle transaction: a single op, tx.gas = 2^24 + R, op success, contract
# deployed, and the bundler's margin.
#
# Rundler must run with reservoir mode available (Glamsterdam active, PR #1351) and bundle the op
# itself; this script never sends handleOps. It uses the harness fixtures already deployed on
# Sepolia: ExecAccount (any signature is accepted), BlobDeployer and, in paymaster mode,
# StatePaymaster (postOp writes a fresh storage slot; needs a staked paymaster or rundler --unsafe).
#
# Usage:
#   BUNDLER_RPC_URL=http://<rundler>:3000 PVG_RPC_URL=<sepolia rpc> \
#     ./scripts/reservoir-e2e.sh [self|paymaster] [size-in-bytes]
#
# Environment:
#   BUNDLER_RPC_URL      rundler JSON-RPC (required)
#   PVG_RPC_URL          Sepolia JSON-RPC for chain reads (required; also read from ../.env)
#   PVG_PRIVATE_KEY      only used to top up the payer's EntryPoint deposit when it is too low
#                        (read from ../.env; never printed)
#   BUNDLER_RPC_HEADER   optional extra curl header for the rundler RPC, e.g. "Authorization: ..."
#   PRIORITY_FEE_WEI     op max priority fee (default 200000000 = 0.2 gwei; Sepolia's rundler
#                        minimum is 0.1 gwei)
#   RECEIPT_TIMEOUT_S    how long to wait for the op to be mined (default 600)
#
# Requires: cast (foundry), jq, curl, bc.

set -euo pipefail

MODE=${1:-self}
SIZE=${2:-24576}
case $MODE in self | paymaster) ;; *) echo "mode must be self or paymaster" >&2; exit 2 ;; esac

DIR=$(cd "$(dirname "$0")/.." && pwd)
if [[ -f $DIR/.env ]]; then
    set -a
    # shellcheck disable=SC1091
    . "$DIR/.env"
    set +a
fi
: "${BUNDLER_RPC_URL:?set BUNDLER_RPC_URL to the rundler RPC}"
: "${PVG_RPC_URL:?set PVG_RPC_URL to a Sepolia RPC}"
PRIORITY_FEE_WEI=${PRIORITY_FEE_WEI:-200000000}
RECEIPT_TIMEOUT_S=${RECEIPT_TIMEOUT_S:-600}

# Harness fixtures on Sepolia (see results/ and docs/reservoir-mode-plan.md)
EP=0x0000000071727De22E5E9d8BAf0edAc6f37da032 # EntryPoint v0.7
ACCOUNT=0xfd5d8F31bDd2A41Aca1866a51C6b11DC0C6fA545 # ExecAccount (v0.7)
DEPLOYER=0xb38d65d1786DE802bE4C481BDdCC9B968A480ff8 # BlobDeployer
PAYMASTER=0x58273F31B0DBBA1B58b22f86244c8D4A344B28CE # StatePaymaster (v0.7)
TX_MAX_GAS_LIMIT=16777216

rpc() {
    local args=(-s -X POST "$BUNDLER_RPC_URL" -H 'content-type: application/json' -d "$1")
    [[ -n ${BUNDLER_RPC_HEADER:-} ]] && args+=(-H "$BUNDLER_RPC_HEADER")
    curl "${args[@]}"
}
call() { # method, params-json
    rpc "$(jq -nc --arg m "$1" --argjson p "$2" '{jsonrpc:"2.0",id:1,method:$m,params:$p}')"
}
fail() { echo "FAIL: $*" >&2; exit 1; }

# The payer's deposit must cover the prefund: about (limits + PVG) * maxFeePerGas.
PAYER=$ACCOUNT
[[ $MODE == paymaster ]] && PAYER=$PAYMASTER
BASE_FEE=$(cast base-fee --rpc-url "$PVG_RPC_URL")
MAX_FEE=$((BASE_FEE * 2 + PRIORITY_FEE_WEI))
NEEDED=$(echo "($SIZE * 1530 + 2000000) * $MAX_FEE * 2" | bc)
DEPOSIT=$(cast call $EP "balanceOf(address)(uint256)" $PAYER --rpc-url "$PVG_RPC_URL" | awk '{print $1}')
if [[ $(echo "$DEPOSIT < $NEEDED" | bc) -eq 1 ]]; then
    : "${PVG_PRIVATE_KEY:?payer deposit $DEPOSIT < $NEEDED wei; set PVG_PRIVATE_KEY to top it up}"
    TOP_UP=$(echo "$NEEDED * 2 - $DEPOSIT" | bc)
    echo "topping up $PAYER deposit by $TOP_UP wei"
    cast send $EP "depositTo(address)" $PAYER --value "$TOP_UP" \
        --private-key "$PVG_PRIVATE_KEY" --rpc-url "$PVG_RPC_URL" --json | jq -c '{tx: .transactionHash, status}'
fi

# The op: ExecAccount.execute(BlobDeployer.deploy(salt, SIZE)) with a fresh salt
NONCE=$(cast call $EP "getNonce(address,uint192)(uint256)" $ACCOUNT 0 --rpc-url "$PVG_RPC_URL" | awk '{print $1}')
SALT=$(cast keccak "reservoir-e2e-$(date +%s)-$RANDOM")
INNER=$(cast calldata "deploy(bytes32,uint256)" "$SALT" "$SIZE")
CALL_DATA=$(cast calldata "execute(address,uint256,bytes)" $DEPLOYER 0 "$INNER")
SIGNATURE=0x$(printf 'ab%.0s' $(seq 65))
OP=$(jq -nc --arg s $ACCOUNT --arg n "$(cast to-hex "$NONCE")" --arg c "$CALL_DATA" --arg sig "$SIGNATURE" \
    --arg mf "$(cast to-hex $MAX_FEE)" --arg pf "$(cast to-hex "$PRIORITY_FEE_WEI")" \
    '{sender:$s,nonce:$n,callData:$c,signature:$sig,maxFeePerGas:$mf,maxPriorityFeePerGas:$pf}')
if [[ $MODE == paymaster ]]; then
    # mode 2: postOp writes a fresh slot; the postOp limit is supplied by the caller, execution
    # only (the slot's state gas comes from the reservoir)
    PM_DATA=$(cast concat-hex 0x02 "$(cast keccak "slot-$SALT")")
    OP=$(echo "$OP" | jq -c --arg pm $PAYMASTER --arg d "$PM_DATA" \
        '. + {paymaster:$pm, paymasterData:$d, paymasterPostOpGasLimit:"0x7530"}')
fi

echo "== estimate ($MODE, $SIZE bytes)"
EST=$(call eth_estimateUserOperationGas "$(jq -nc --argjson op "$OP" --arg ep $EP '[$op,$ep]')")
echo "$EST" | jq -c .
echo "$EST" | jq -e .result >/dev/null || fail "estimation failed"
OP=$(echo "$OP" | jq -c --argjson e "$(echo "$EST" | jq .result)" \
    '. + {preVerificationGas:$e.preVerificationGas, callGasLimit:$e.callGasLimit,
          verificationGasLimit:$e.verificationGasLimit}
       + (if $e.paymasterVerificationGasLimit then {paymasterVerificationGasLimit:$e.paymasterVerificationGasLimit} else {} end)')

echo "== send"
SEND=$(call eth_sendUserOperation "$(jq -nc --argjson op "$OP" --arg ep $EP '[$op,$ep]')")
echo "$SEND" | jq -c .
OP_HASH=$(echo "$SEND" | jq -r '.result // empty')
[[ -n $OP_HASH ]] || fail "send failed"

echo "== waiting up to ${RECEIPT_TIMEOUT_S}s for the bundle"
RECEIPT=null
for ((i = 0; i < RECEIPT_TIMEOUT_S / 5; i++)); do
    RECEIPT=$(call eth_getUserOperationReceipt "[\"$OP_HASH\"]" | jq -c '.result')
    [[ $RECEIPT != null ]] && break
    sleep 5
done
[[ $RECEIPT != null ]] || fail "op $OP_HASH not mined within ${RECEIPT_TIMEOUT_S}s (is the builder skipping it? check SkipReason in rundler logs)"
TX=$(echo "$RECEIPT" | jq -r .receipt.transactionHash)

echo "== result"
TX_GAS=$(cast tx "$TX" gas --rpc-url "$PVG_RPC_URL")
RC=$(cast receipt "$TX" --rpc-url "$PVG_RPC_URL" --json)
GAS_USED=$(echo "$RC" | jq -r .gasUsed | xargs cast to-dec)
PRICE=$(echo "$RC" | jq -r .effectiveGasPrice | xargs cast to-dec)
OP_EVENT=$(cast keccak "UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)")
OPS_IN_BUNDLE=$(echo "$RC" | jq --arg t "$OP_EVENT" '[.logs[] | select(.topics[0]==$t)] | length')
DEPLOYED=$(echo "$RC" | jq --arg t "$(cast keccak "Deployed(address,uint256)")" '[.logs[] | select(.topics[0]==$t)] | length')
SUCCESS=$(echo "$RECEIPT" | jq -r .success)
CHARGED=$(echo "$RECEIPT" | jq -r .actualGasUsed | xargs cast to-dec)
COST=$(echo "$RECEIPT" | jq -r .actualGasCost | xargs cast to-dec)
RESERVOIR=$((TX_GAS - TX_MAX_GAS_LIMIT))

echo "op hash          $OP_HASH"
echo "bundle tx        $TX"
echo "tx status        $(echo "$RC" | jq -r .status)"
echo "ops in bundle    $OPS_IN_BUNDLE"
echo "tx.gas           $TX_GAS (2^24 + R, R = $RESERVOIR)"
echo "op success       $SUCCESS"
echo "contract deployed $DEPLOYED"
echo "gas: charged $CHARGED, used $GAS_USED, margin $((CHARGED - GAS_USED))"
echo "wei: op paid $COST, bundle cost $(echo "$GAS_USED * $PRICE" | bc), margin $(echo "$COST - $GAS_USED * $PRICE" | bc)"

[[ $(echo "$RC" | jq -r .status) == 0x1 ]] || fail "bundle transaction reverted"
[[ $OPS_IN_BUNDLE == 1 ]] || fail "reservoir-mode op was not bundled alone"
[[ $RESERVOIR -gt 0 ]] || fail "bundle has no reservoir (tx.gas <= 2^24)"
[[ $SUCCESS == true ]] || fail "op failed"
[[ $DEPLOYED == 1 ]] || fail "contract not deployed"
[[ $CHARGED -ge $GAS_USED ]] || fail "bundler under-recovered: charged $CHARGED < used $GAS_USED"
echo "PASS"
