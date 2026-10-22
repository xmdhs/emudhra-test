#!/usr/bin/env python3
"""Build app/src/main/assets/tests.json from the eMudhra incident page.

The incident page publishes `chains.zip`, which holds the exact certificate
chain served by each of the twelve test hosts. Bundling those chains lets the
Android app evaluate them against the device's own platform trust store with no
network access at all -- which is the point: a network client would also be
testing connectivity, not just trust.

Run this script once (or when the upstream data changes) and commit the output.

Usage: python3 tools/fetch_data.py
"""

import io
import json
import pathlib
import urllib.request
import zipfile

BASE = "https://emudhra.we-have-a-problem.com"
ASSETS = pathlib.Path(__file__).resolve().parent.parent / "app" / "src" / "main" / "assets"


def fetch_bytes(path: str) -> bytes:
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=60) as resp:
        return resp.read()


def fetch_json(path: str):
    return json.loads(fetch_bytes(path))


def main() -> None:
    roots = fetch_json("roots.json")
    archive = zipfile.ZipFile(io.BytesIO(fetch_bytes("chains.zip")))

    chains = []
    for name in sorted(archive.namelist()):
        if not name.endswith(".pem"):
            continue
        host = pathlib.Path(name).name[: -len(".pem")]
        # dv-g3b-emudhra.we-have-a-problem.com
        # dv-g3b-aaa-emudhra.we-have-a-problem.com
        slug = host[: -len("-emudhra.we-have-a-problem.com")]
        cross_signed = slug.endswith("-aaa")
        if cross_signed:
            slug = slug[: -len("-aaa")]
        kind, generation = slug.split("-", 1)
        chains.append(
            {
                "host": host,
                "kind": kind.upper(),
                "generation": generation.upper(),
                "root": "AAA Certificate Services" if cross_signed else "emSign Root TLS CA - G3",
                "cross_signed": cross_signed,
                "pem": archive.read(name).decode("ascii"),
            }
        )

    data = {
        "source": f"{BASE}/",
        "captured": "2026-10-20",
        "chains": chains,
        "roots": [
            {"name": r["name"], "sha256": r["sha256"], "role": r["role"], "pem": r["pem"]}
            for r in roots
        ],
    }

    ASSETS.mkdir(parents=True, exist_ok=True)
    (ASSETS / "tests.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(chains)} chains and {len(data['roots'])} roots to {ASSETS / 'tests.json'}")


if __name__ == "__main__":
    main()
