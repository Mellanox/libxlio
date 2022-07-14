#!/usr/bin/env python3

import sys
from pathlib import Path
from elastic_tools import elastic_query, find_baseline

fail_treshold = 0.95  # fail Jenkins run if current benchmark result is worse than baseline by 5% or more
benchmark_ids_file = Path(sys.argv[0]).parent / "../reports" / "report_ids.txt"
exit_code = 0


def get_benchmark(benchmark_id):
    data = elastic_query()
    for d in data:
        if d["_source"].get("benchmark_id") == benchmark_id:
            return d["_source"]


def get_baseline(bench):
    def select_fields(b):
        return set([b[f] for f in ("Proto(http/https)", "Workers", "Payload")])

    all_baselines = find_baseline(bench["type"], bench["mode"])
    for base in all_baselines:
        if select_fields(base["_source"]) == select_fields(bench):
            return base["_source"]


def compare_to_baseline(benchmark_id):
    return bench["Rate(RPS)"] / base["Rate(RPS)"]


def check_benchmark():
    global exit_code
    with open(benchmark_ids_file) as f:
        try:
            for benchmark_id in [line.strip() for line in f]:
                bench = get_benchmark(benchmark_id)
                assert bench is not None, f"Cannot find benchmark data in Elastic for {benchmark_id=}"
                bench_rps = bench.get("Rate(RPS)")
                assert bench_rps is not None, f"Cannot get current benchmark's RPS ({benchmark_id=}, failing the check"
                base = get_baseline(bench)
                if base:
                    base_rps = base["Rate(RPS)"]
                    res = round(bench_rps / base_rps, 2)
                    if res > fail_treshold:
                        print(f"Benchmark {benchmark_id} is OK compared to the baseline.")
                    else:
                        print(f"""Benchmark {benchmark_id} has FAILED: it is {res} of the baseline result (expected to be at least {fail_treshold}). Benchmarked RPS: {bench_rps}, baseline RPS: {base_rps}, benchmark parameters: proto={bench["Proto(http/https)"]}, payload={bench["Payload"]}, bulk type={bench["type"].upper()}""")
                        print("It's safe to ignore this check right now.")
                        exit_code = 1
                else:
                    print("There is no baseline value for this benchmark")
        except AssertionError as e:
            print(e)
            exit_code = 1


if __name__ == "__main__":
    check_benchmark()
    sys.exit(exit_code)
