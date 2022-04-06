# nmon-utils.sh
# helper functions to monitor stats with nmon

# start nmon in background and return PID of newly created process
nmon_start()
{
    nmon -p -s1 -f -m "${1:-.}"
}

# stop nmon instance by PID
nmon_stop()
{
    [[ -z "$1" ]] || kill "$1"
}

# parse and print nmon csv in specified folder
nmon_parse()
{
    local -r dir=${1:-.}
    local -r offset=${2:-1}
    echo "parsing nmon at $dir"

    for f in $(find "$dir" -maxdepth 1 -name "*.nmon"); do
        echo "found nmon stats - $f"
        paste -d, <(cat "$f" | nmon_parse_cpu "$offset") <(cat "$f" | nmon_parse_mem "$offset") | column -s, -t
    done
}

# get avarage cpu usage and number of cores
nmon_parse_cpu()
{
    grep "^CPU_ALL" | sort | tail -n +2 | tail -n "+$1" | awk -F, -v OFS="," '{t+=$6; n++} NR==1 {c=$9} END {print "cpuload", "cpucount"; print 100-t/n, c}'
}

# get mem and swap usage diff
nmon_parse_mem()
{
    grep "^MEM" | sort | cut -d, -f3,6,7,10 | tail -n +2 | tail -n "+$1" | awk -F, -v OFS=, -f <(cat - <<- "EOF"
        {
            if((!mlo)||(mlo>$3)) mlo=$3
            if((!mhi)||(mhi<$3)) mhi=$3

            if((!slo)||(slo>$4)) slo=$4
            if((!shi)||(shi<$4)) shi=$4
        }

        NR==1 {
            mt=$1
            st=$2
        }

        END {
            print "memmin", "memmax", "memdiff", "memtotal", "swapmin", "swapmax", "swapdiff", "swaptotal"
            print mlo, mhi, mhi - mlo, mt, slo, shi, shi - slo, st
        }
EOF
    )
}
