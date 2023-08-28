#!/bin/bash 
# Launcher script for the rundler.

export TAG=latest
cd `dirname \`realpath $0\``
case $1 in

 name)
	echo "rundler/$TAG"
	;;

 start)
	cast send --from $(cast rpc eth_accounts | tail -n 1 | tr -d '[]"') --unlocked --value 1ether 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 > /dev/null
    cd ../../bundler-spec-tests/@account-abstraction && yarn deploy --network localhost
	;;
 stop)
	echo "stopping"
	;;

 *)
	echo "usage: $0 {start|stop|name}"
esac
