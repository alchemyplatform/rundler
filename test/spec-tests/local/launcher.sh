#!/bin/bash 
# Launcher script for geth and the entrypoint
set +x
cd `dirname \`realpath $0\``
case $1 in

 start)
	docker-compose up -d
	sleep 10
	cast send --unlocked --from $(cast rpc eth_accounts | tail -n 1 | tr -d '[]"') --value 100ether 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 > /dev/null
	(cd ../$2/bundler-spec-tests/@account-abstraction && yarn deploy --network localhost)
	../../../target/debug/rundler node --log.file out.log &
	while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' localhost:3000/health)" != "200" ]]; do sleep 1 ; done
	;;
 stop)
	pkill rundler
	docker-compose down -t 3
	;;

 *)
  cat <<EOF
usage:
  $0 start {v0_6|v0_7}
  $0 stop
EOF
esac
