import sys
import csv
import re
from pathlib import Path
from elasticsearch import Elasticsearch
from datetime import datetime


ELASTIC_HOST = "dev-r-vrt-018.mtr.labs.mlnx"
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


if __name__ == "__main__":
    for fn in sys.argv[1:]:
        export_csv_file(fn)
