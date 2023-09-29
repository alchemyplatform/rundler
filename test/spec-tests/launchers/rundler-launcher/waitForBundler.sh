#!/bin/bash 
rpcurl=$1
timeout=${2:-10}

if [ -z "$rpcurl" ]; then
echo $0 {rpcurl} [timeout]
exit 2
fi

for ((i=0; i<$timeout; i++ )); do

  resp=`curl -s  -H "content-type: application/json" -d '{"method":"eth_chainId","params":[]}' $rpcurl`
  echo $resp
  echo $resp | grep -q '"result"'  && exit 0
  sleep 1

done
echo Timed-out waiting for $rpcurl
exit 1