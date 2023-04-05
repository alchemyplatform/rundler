#!/bin/bash 
# Launcher script for geth and the entrypoint
set +x
cd `dirname \`realpath $0\``
case $1 in

 start)
	docker-compose up -d
	sleep 10
    (cd ../bundler-spec-tests/@account-abstraction && yarn deploy --network localhost)
	../../../target/debug/rundler node --log.file out.log &
	while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' localhost:8080/health)" != "200" ]]; do sleep 1; done
	;;
 stop)
	pkill rundler
 	docker-compose down -t 3
	;;

 *)
	echo "usage: $0 {start|stop|name}"
esac
