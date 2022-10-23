import sys
import csv
import re
from pathlib import Path
from elasticsearch import Elasticsearch
from datetime import datetime
import itertools


ELASTIC_HOST = "r-elk.mtr.labs.mlnx"
INDEX = "xlio_perf"

elastic = Elasticsearch([
    {"host": ELASTIC_HOST}
])

elastic.indices.create(index=INDEX, ignore=400)


def guess_type(string):
    if re.match(r'^\d+$', string):
        return int
    elif re.match(r'^[\d\.]+$', string):
        return float
    else:
        return str


def fix_type(field):
    guess = guess_type(str(field))
    if guess != type(field):
        field = guess(field)
    return field


def parse_csv_file(filename):
    with open(filename, newline="") as csvfile:
        data = []
        for row in csv.DictReader(csvfile):
            data = {k: fix_type(v) for k, v in row.items()}
            data["run_id"] = Path(fn).stem
        return data


def export_csv_file(filename):
    print(f"Exporting {filename} to Elasticsearch")
    export_snapshot(filename, parse_csv_file(filename))
    print(f"Done exporting {fn}.")


def export_snapshot(prefix, data):
    doc_id = f"{prefix}_{data['ID']}"
    data["@timestamp"] = datetime.now().isoformat()
    elastic.index(index=INDEX, id=doc_id, document=data)


def make_query(**kwargs):
    terms = []
    for k, v in kwargs.items():
        terms.append({"term": {k: v}})
    expr = {
        "bool": {
            "filter": terms,
        }
    }
    return expr


def elastic_query(**kwargs):
    return elastic.search(index=INDEX, size=10000, query=make_query(**kwargs))["hits"]["hits"]


def find_baseline(bulk_type, mode):
    return elastic_query(is_baseline=True, mode=mode, type=bulk_type)


def remove_baseline(bulk_type, mode):
    for r in find_baseline(bulk_type, mode):
        elastic.update(INDEX, r["_id"], {"doc":{"is_baseline": False}})


def branch_head(branch_id, **kwargs):
    ret = sorted(filter_docs(elastic_query(branch=branch_id), **kwargs), key=lambda x: x["_source"]['@timestamp'], reverse=True)
    if ret:
        return ret[0]


def all_permutations(variants):
    keys, vals = zip(*variants.items())
    return [dict(zip(keys, v)) for v in itertools.product(*vals)]


def move_branch_head(branch_id):
    all_docs = elastic_query(branch=branch_id)
    def variants(field):
        return set([e["_source"][field] for e in all_docs])

    keys = {k: variants(k) for k in ["Proto(http/https)", "Workers", "Payload", "type"]}
    values = all_permutations(keys)
    for params in values:
        docs = filter_docs(all_docs, **params)
        for d in docs:
            print(f"Removing branch {branch_id} head ({params}) from document {d['_source'].get('benchmark_id')}")
            elastic.update("xlio_perf", d["_id"], {"doc": {"is_head": False}})
        head = branch_head(branch_id, **params)
        if head:
            print(f"Setting branch {branch_id} head ({params}) to document {head['_source'].get('benchmark_id')}")
            elastic.update("xlio_perf", head["_id"], {"doc": {"is_head": True}})


def filter_docs(docs, **kwargs):
    ret = []
    for d in docs:
        match = True
        for k, v in kwargs.items():
            if k not in d["_source"] or d["_source"][k] != v:
                match = False
                break
        if match:
            ret.append(d)
    return ret


if __name__ == "__main__":
    for fn in sys.argv[1:]:
        export_csv_file(fn)
