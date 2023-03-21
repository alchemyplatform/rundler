#!/bin/bash 
# Launcher script for the alchemy-bundler.

export TAG=latest
cd `dirname \`realpath $0\``
case $1 in

 name)
	echo "alchemy-bundler/$TAG"
	;;

 start)
	docker-compose up -d --wait
    cd ../../bundler-spec-tests/@account-abstraction && yarn deploy --network localhost
	;;
 stop)
 	docker-compose down -t 3
	;;

 *)
	echo "usage: $0 {start|stop|name}"
esac
