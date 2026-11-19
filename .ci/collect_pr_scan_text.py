#!/usr/bin/env python3
"""Fetch this pull request's commit messages, description, and comments into
secret_scan_context/ so the filesystem secret scan reads them too.
Does nothing outside a pull request build."""

import json
import os
import sys
import urllib.request
from pathlib import Path


def main():
    pull = os.environ.get("ghprbPullId")
    if not pull:
        print("secret scan: no ghprbPullId, skip pull request text")
        return 0
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("secret scan: GITHUB_TOKEN is empty", file=sys.stderr)
        return 1

    api = "https://api.github.com/repos/" + os.environ["ghprbGhRepository"]
    try:
        pr = get(token, f"{api}/pulls/{pull}")
        commits = get_all(token, f"{api}/pulls/{pull}/commits")
        comments = (get_all(token, f"{api}/issues/{pull}/comments")
                    + get_all(token, f"{api}/pulls/{pull}/comments")
                    + get_all(token, f"{api}/pulls/{pull}/reviews"))
    except (OSError, ValueError) as exc:
        print(f"secret scan: cannot fetch pull request text: {exc}", file=sys.stderr)
        return 1

    texts = {
        "commit_messages.txt": [f"commit {c['sha']}\n{c['commit']['message']}" for c in commits],
        "pr_description.txt": [pr["title"], pr["body"]],
        "pr_comments.txt": [c["body"] for c in comments],
    }
    out = Path(os.environ["WORKSPACE"], "secret_scan_context")
    out.mkdir(exist_ok=True)
    for name, parts in texts.items():
        data = ("\n\n".join(p for p in parts if p) + "\n").encode()
        (out / name).write_bytes(data)
        print(f"secret scan: wrote {out.name}/{name} ({len(data)} bytes)")
    return 0


def get(token, url):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def get_all(token, url):
    items, page = [], 1
    while True:
        batch = get(token, f"{url}?per_page=100&page={page}")
        items += batch
        if len(batch) < 100:
            return items
        page += 1


if __name__ == "__main__":
    sys.exit(main())
