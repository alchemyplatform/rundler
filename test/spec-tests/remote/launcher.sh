#!/bin/bash 
# Launcher script for the rundler.

export TAG=latest
export DISABLE_ENTRY_POINT_V0_6=false
export DISABLE_ENTRY_POINT_V0_7=false
cd `dirname \`realpath $0\``
case $1 in

 name)
	echo "rundler/$TAG"
	;;

 start)
	case $2 in
		v0_6)
		export DISABLE_ENTRY_POINT_V0_7=true
		;;
		v0_7)
		export DISABLE_ENTRY_POINT_V0_6=true
		;;
		*)
    cat <<EOF
usage:
  $0 start {v0_6|v0_7}
  $0 stop
EOF
		exit 1
	esac
	docker-compose up -d --wait
	cast send --unlocked --from $(cast rpc eth_accounts | tail -n 1 | tr -d '[]"') --value 1ether 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 > /dev/null
	cd ../$2/bundler-spec-tests/@account-abstraction && yarn deploy --network localhost
	;;
 stop)
 	docker-compose down -t 3
	;;

 *)
  cat <<EOF
usage:
  $0 name
  $0 start {v0_6|v0_7}
  $0 stop
EOF
esac
