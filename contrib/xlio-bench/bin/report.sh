#!/bin/bash -eu

SOURCE_DIR=${1:-.}
WORK_DIR=$(mktemp -d)

cleanup()
{
    [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}

trap cleanup EXIT

process_id()
{
    local id=$1
    echo $id

    local server_dir=$(find $SOURCE_DIR -maxdepth 1 -type d -name "$id-server*" | head -n1)
    local client_dir=$(find $SOURCE_DIR -maxdepth 1 -type d -name "$id-client-*" | head -n1)

    source $client_dir/conf
    source $server_dir/conf

    local tp=$(cat "$client_dir/wrk.out" | grep "Transfer/sec" | tr -s ' ' | cut -d' ' -f2 | tr -d 'B' | numfmt --from=iec --round=down | awk '{printf "%.3f", $0/(1024*1024*1024)}')
    local rps=$(cat "$client_dir/wrk.out" | grep "Requests/sec" | tr -s ' ' | cut -d' ' -f2)
    #local cpu=$(cat "$server_dir/nmon.csv" | grep CPU_ALL | sort | tail -n +11 | awk -F, '{t+=(100-$6)*$9; n++} END {printf "%.3f\n", t/n}')
    local cpu=$(cat $server_dir/*.nmon | grep CPU_ALL | sort | tail -n +11 | awk -F, '{t+=$6; n++} END {printf "%.3f\n", 100-t/n}')
    local cpus=$(cat $server_dir/*.nmon | grep "AAA,cpus," | cut -d, -f3)
    #local cpg=$(printf "%.3f" $(echo "$cpu / $tp" | bc -l))
    #local cpr=$(printf "%.6f" $(echo "$cpu / $rps" | bc -l))

    #echo "$id,$mode,$proto,$workers,$payload,$tp,$rps,$cpu,$cpg,$cpr" >> $WORK_DIR/report.csv
    echo "$id,$mode,$proto,$workers,$payload,$tp,$rps,$cpu,$cpus" >> $WORK_DIR/report.csv
}

# print header
#echo "id,mode(ktls/xlio),proto(http/https),workers,payload,throughput(Gbps),rate(RPS),cpu(%),cpu/Gbps,cpu/RPS" > $WORK_DIR/report.csv
echo "ID,Mode(ktls/xlio),Proto(http/https),Workers,Payload,Throughput(Gbps),Rate(RPS),CPU(%),CPUs" > $WORK_DIR/report.csv

# process all available benchmark artifacts
ID_LIST=$(ls -1 $SOURCE_DIR | grep -E "[0-9]+-(client|server)-.*" | cut -d'-' -f1 | sort -u)
for id in $ID_LIST; do
    process_id $id
done

mv $WORK_DIR/report.csv ./
