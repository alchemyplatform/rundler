#!/bin/bash 
# Launcher script for the rundler.

export TAG=latest
cd `dirname \`realpath $0\``

case $1 in
	v0_6)
	export ENTRY_POINT_V0_6_ENABLED=true
	export ENTRY_POINT_V0_7_ENABLED=false
	;;
	v0_7)
	export ENTRY_POINT_V0_6_ENABLED=false
	export ENTRY_POINT_V0_7_ENABLED=true
	;;
	*)
	echo "usage: $0 {v0_6|v0_7} {start|stop|name}"
	exit 1
esac


case $2 in

 name)
	echo "rundler/$TAG"
	;;

 start)
	docker-compose up -d --wait
	cast send --unlocked --from $(cast rpc eth_accounts | tail -n 1 | tr -d '[]"') --value 1ether 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 > /dev/null
    cd ../$1/bundler-spec-tests/@account-abstraction && yarn deploy --network localhost
	;;
 stop)
 	docker-compose down -t 3
	;;

 *)
	echo "usage: $0 {v0_6|v0_7} {start|stop|name}"
esac
