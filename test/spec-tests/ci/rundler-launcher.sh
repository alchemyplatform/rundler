#!/bin/bash 
# Launcher script for the rundler.
set -x
export TAG=latest
cd `dirname \`realpath $0\``
case $1 in

 name)
    echo "rundler/$TAG"
    ;;

 start)
    docker-compose up -d
    cast send --from $(cast rpc eth_accounts | tr -d '[]"') --value 1ether 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 > /dev/null
    cd ../bundler-spec-tests/@account-abstraction && yarn deploy --network localhost
    ;;
 stop)
    docker-compose down -t 3
    ;;

 *)
    echo "usage: $0 {start|stop|name}"
esac
