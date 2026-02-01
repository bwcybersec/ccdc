#! /usr/bin/env bash

# break glass
general=(20 21 22 25 53 80 110 123 143 161 389 443 514 993 995 8000 8089 8191 8443 9997)

ecom=(80 161 443 514 8089 9997)
webmail=(25 110 161 993 995 8089 9997)
splunk=(161 514 8000 8089 8191 9997)
wkst=(161 8089 9997)

MACHINE=$ZDS_TYPE

function help {
  echo "Usage: $(basename $0) [option] [interface] - simple xdp-filter helper script"
  echo ""
  echo "-a, --all		disable XDP filtering on all interfaces"
  echo "-o, --off		disable XDP filtering on the specified interface"
  echo "-p, --permissive	use generalized port list"
  echo "-r, --restrictive	use role-based port list"
  echo "-s, --status		print current status"
  echo "-h, --help		print this help text"
  echo ""
}

if [[ ! -x $(which xdp-filter) ]]; then
  echo "Error: xdp-filter not present, verify xdp-tools is installed"
  exit 1
fi

if [[ $1 == -h || $1 == --help ]]; then
  help
  exit 0

elif [[ $1 == -s || $1 == --status ]]; then
  xdp-filter status

elif [[ $1 == -a || $1 == --all ]]; then
  xdp-filter unload --all

elif [[ $1 == -o || $1 == --off ]]; then
  xdp-filter unload $2

elif [[ $1 == -p || $1 == --permissive ]]; then
  xdp-filter load $2 -p deny || exit 1
  for i in ${general[@]}; do
    xdp-filter port $i
  done

elif [[ $1 == -r || $1 == --restrictive ]]; then
  xdp-filter load $2 -p deny || exit 1
  if [[ $MACHINE == "ecom" ]]; then
    for i in ${ecom[@]}; do
      xdp-filter port $i
    done
  
  elif [[ $MACHINE == "webmail" ]]; then
    for i in ${webmail[@]}; do
      xdp-filter port $i
    done
  
  elif [[ $MACHINE == "splunk" ]]; then
    for i in ${splunk[@]}; do
      xdp-filter port $i
    done
  
  elif [[ $MACHINEE == "wkst" ]]; then
    for i in ${wkst[@]}; do
      xdp-filter port $i
    done
  
  else
    echo "Error: invalid ZDS_TYPE, check env" && exit 1
  fi

else
  echo "Error: no valid options specified, see help page (-h)" && exit 1
fi

