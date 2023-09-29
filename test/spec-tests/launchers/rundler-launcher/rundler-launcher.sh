#!/bin/bash
#launcher script for the AA reference bundler.
# copied from https://github.com/eth-infinitism/bundler/blob/main/dockers/test/aabundler-launcher.sh

export TAG=latest
cd `dirname \`realpath $0\``
case $1 in

 name)
	echo "rundler/$TAG"
	;;

 start)
	docker-compose up -d --wait
	echo waiting for bundler to start
	./waitForBundler.sh http://localhost:3000
	;;
 stop)
	docker-compose logs rundler --no-log-prefix > /tmp/rundler.log
	echo dumped rundler log to /tmp/bundler.log
 	docker-compose down -t 1
	;;

 *)
	echo "usage: $0 {start|stop|name}"
esac
