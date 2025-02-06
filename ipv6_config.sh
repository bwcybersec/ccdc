#!/bin/bash 

RED=`tput setaf 1`                          # code for red console text
GREEN=`tput setaf 2`                        # code for green text
YELLOW=`tput setaf 3`                       # code for yellow text
NC=`tput sgr0`                              # Reset the text color


var=""
function prompt {
	#[prompt] [variable]
	read -p "$1" var
	if [[ -z "$var" ]]; then
		echo "${RED}Please enter valid response${NC}" 
        exit -1
	fi
}

function enable_ipv6() {

    echo "$FUNCNAME: ${GREEN}Enabling IPv6...${NC}"

    sysctl_config_file="/etc/sysctl.conf"

    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sysctl -w net.ipv6.conf.default.disable_ipv6=0
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0

    echo "$FUNCNAME: ${GREEN}Reloading sysctl so the changes take place...${NC}"

    sysctl -p

}

function disable_ipv6() {

    echo "$FUNCNAME: ${GREEN}Disabling IPv6...${NC}"

    sysctl_config_file="/etc/sysctl.conf"

    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1

    echo "$FUNCNAME: ${GREEN}Reloading sysctl so the changes take place...${NC}"

    sysctl -p

}

function deb_config_ipv6() {

    ip -6 addr add 2001:db8:2::200/64 dev ens33
    ip -6 route add  default via 2001:db8:2::1 dev ens33

}


function ubu_web_config_ipv6() {

    ip -6 addr add 2001:db8:1::200/64 dev ens33
    ip -6 route add  default via 2001:db8:1::1 dev ens33

}

function ubu_work_config_ipv6() {

    ip -6 addr add 2001:db8:1::100/64 dev ens33
    ip -6 route add default via 2001:db8:1::1 dev ens33

}

function panic(){
    echo "$FUNCNAME: ${RED}fatal error${NC}"
    exit -1
}

function main {

    prompt "${GREEN}Enter a choice: ${YELLOW}[local, routing, disable]${NC} " host

    if [[ "$var" == "local" ]]; then

        # prompt user for host name
        prompt "${GREEN}What is your host?: ${YELLOW}ubu_web, ubu_work, deb${NC}    " host

        # ubu web commands
        if [[ "$var" == "ubu_web"]]; then
            
            echo "${GREEN}Setting up ubu_web...${NC}"

            enable_ipv6 || panic
            ubu_web_config_ipv6 || panic

        fi

        #ubu workstation commands
        if [[ "$var" == "ubu_work"]]; then
            
            echo "${GREEN}Setting up ubu_work...${NC}"

            enable_ipv6 || panic
            ubu_work_config_ipv6 || panic

        fi

        echo "${Green}IPv6 is configured, make sure to disable it when done...${NC}"

    elif [[ "$var" == "routing" ]]; then

        echo "${YELLOW}Make sure you configure a linux box on the User and Internal subnets, a Windows box, and the PAN!${NC}"

        # prompt user for host name
        prompt "${GREEN}What is your host?: ${YELLOW}ubu_web, ubu_work, deb${NC}    " host

        # ubu web commands
        if [[ "$var" == "ubu_web"]]; then
            
            echo "${GREEN}Setting up ubu_web...${NC}"

            enable_ipv6 || panic
            ubu_web_config_ipv6 || panic

        fi

        #ubu workstation commands
        if [[ "$var" == "ubu_work"]]; then
            
            echo "${GREEN}Setting up ubu_work...${NC}"

            enable_ipv6 || panic
            ubu_work_config_ipv6 || panic

        fi

        # debian commands
        if [[ "$var" == "deb"]]; then
            
            echo "${GREEN}Setting up ubu_work...${NC}"

            enable_ipv6 || panic
            deb_config_ipv6 || panic

        fi

        echo "${Green}IPv6 is configured, make sure to disable it when done...${NC}"

    elif [[ "$var" == "disable" ]]; then

        disable_ipv6 || panic

        echo "${Green}IPv6 is disabled...${NC}"

    else
        echo "${RED}Please enter a valid response...${NC}"
        exit -1
    fi
    exit 0
}

if [[ "$UID" != "0" ]]; then
    echo "$0: ${RED}you must be root to configure this box.${NC}"
    exit -1
fi

main "$@"