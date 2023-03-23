#!/bin/bash 
# Launcher script for geth and the entrypoint
set +x
cd `dirname \`realpath $0\``
case $1 in

 start)
	docker-compose up -d
	sleep 10
    (cd ../bundler-spec-tests/@account-abstraction && yarn deploy --network localhost)
	../../../target/debug/alchemy-bundler bundler --log.file out.log &
	;;
 stop)
	pkill alchemy-bundler
 	docker-compose down -t 3
	;;

 *)
	echo "usage: $0 {start|stop|name}"
esac
