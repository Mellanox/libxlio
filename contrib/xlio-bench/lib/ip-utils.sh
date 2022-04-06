# helper functions to work with ip addresses

ip_dot2hex()
{
    # ip_dot2hex 10.0.0.1 -> 0A000001
    printf '%02X' $(echo ${1//./ })
}


ip_hex2dot()
{
    # ip_hex2dot 0A000001 -> 10.0.0.1
    printf '%d.%d.%d.%d' $(echo "$1" | sed 's/../0x& /g')
}

ip_seq()
{
    # ip_seq 5 10.0.0.1 24 -> generate sequence of 5 ip addresses starting from 10.0.0.2/24
    local -r _count="$1"
    local -r _address_hex="$(ip_dot2hex $2)"
    local -r _prefix="${3:+/$3}"

    for i in $(seq "$_count"); do
        local ip_hex=$(printf "%08X" $((0x$_address_hex + i)))
        echo "$(ip_hex2dot $ip_hex)$_prefix"
    done
}

ip_alias()
{
    # ip_alias {add|del} ens3f0 address... -> add/del addresses for device ens3f0
    local -r _action="$1"
    local -r _device="$2"
    shift 2

    for a in $@; do
        sudo ip address "$_action" "$a" dev "$_device" || true
    done
}
