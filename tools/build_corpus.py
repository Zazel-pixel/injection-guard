#!/usr/bin/env python3
"""Rebuild corpus/external/*.jsonl from pinned upstream files.

The committed JSONL files are what evaluate.py reads; this script only exists
so that anyone can check they were derived faithfully. Every upstream file is
pinned by revision AND by sha256: a silent upstream change fails loudly.

    python3 tools/build_corpus.py --fetch DIR      # download into DIR (stdlib)
    uv run --no-project --with pyarrow==22.0.0 \\
        python3 tools/build_corpus.py --build DIR  # convert (parquet needs pyarrow)

Downloaded files are untrusted data: keep DIR outside the repository.
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "corpus" / "external"

INJECAGENT_REV = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
DEEPSET_REV = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
LAKERA_REV = "04737b65e90a6794ec227012e4a255a7def6344b"

_GH = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/" + INJECAGENT_REV
_HF = "https://huggingface.co/datasets/{}/resolve/{}/{}"

# local name -> (url, sha256)
FILES = {
    "injecagent_test_cases_dh_base.json": (
        _GH + "/data/test_cases_dh_base.json",
        "0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305"),
    "injecagent_test_cases_dh_enhanced.json": (
        _GH + "/data/test_cases_dh_enhanced.json",
        "885602716b72c18af80695ce6c2e1f242fa03163bc90b0788b0c5e4ab6216d50"),
    "injecagent_test_cases_ds_base.json": (
        _GH + "/data/test_cases_ds_base.json",
        "4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9"),
    "injecagent_test_cases_ds_enhanced.json": (
        _GH + "/data/test_cases_ds_enhanced.json",
        "7bc510868df032511053fc40e8470e68a041fb7148d055112093594bf73ab0ce"),
    "deepset_train.parquet": (
        _HF.format("deepset/prompt-injections", DEEPSET_REV,
                   "data/train-00000-of-00001-9564e8b05b4757ab.parquet"),
        "2e10bc7ab30f542c97e4e83e2a5683000b5057d25ec10908784c631d44124c04"),
    "deepset_test.parquet": (
        _HF.format("deepset/prompt-injections", DEEPSET_REV,
                   "data/test-00000-of-00001-701d16158af87368.parquet"),
        "39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e"),
    "lakera_train.parquet": (
        _HF.format("Lakera/gandalf_ignore_instructions", LAKERA_REV,
                   "data/train-00000-of-00001-ded53be747ff55cd.parquet"),
        "5b6acf3e5a5998d21f8e1222bb45bbdec25a14408747b1cd63bebef4a75fa439"),
    "lakera_validation.parquet": (
        _HF.format("Lakera/gandalf_ignore_instructions", LAKERA_REV,
                   "data/validation-00000-of-00001-94481a2a09ff2fff.parquet"),
        "f51ab3e3407a368845b0f57932cc745c09280429416d7507bd178a16326a79f6"),
    "lakera_test.parquet": (
        _HF.format("Lakera/gandalf_ignore_instructions", LAKERA_REV,
                   "data/test-00000-of-00001-bc92128b9288a6d1.parquet"),
        "56b646d133335ebc535266bd55dbe1b5bee7caa4b95bf49d040684b9b5dd9972"),
}

PLACEHOLDER = "<Attacker Instruction>"

# deepset mixes English and German without a language column. A crude
# function-word count is enough to split them for reporting purposes.
_GERMAN = re.compile(
    r"\b(und|der|die|das|ist|nicht|ich|sie|wie|was|ein|eine|mit|für|auf|"
    r"auch|du|bitte|vergiss|alle|ignoriere|sind|wir|ihr|dem|den|zu|von|"
    r"warum|wieso|kann|soll|über)\b", re.I)


def guess_lang(text):
    words = max(1, len(text.split()))
    return "de" if len(_GERMAN.findall(text)) / words > 0.12 else "en"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(dest):
    dest.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in FILES.items():
        target = dest / name
        if not target.exists():
            print(f"fetch {name}")
            with urllib.request.urlopen(url, timeout=60) as resp:
                target.write_bytes(resp.read())
        if sha256(target) != digest:
            sys.exit(f"sha256 mismatch for {name}: refusing to use it")
    print(f"{len(FILES)} files verified in {dest}")


def verified(src):
    for name, (_, digest) in FILES.items():
        if sha256(src / name) != digest:
            sys.exit(f"sha256 mismatch for {name}")


def rows(path):
    import pyarrow.parquet as pq  # only needed to rebuild, not to evaluate
    return pq.read_table(path).to_pylist()


def write(name, records):
    OUT.mkdir(parents=True, exist_ok=True)
    seen, kept = set(), []
    for rec in records:
        key = (rec["label"], rec["text"])
        if key not in seen:
            seen.add(key)
            kept.append(rec)
    with (OUT / name).open("w", encoding="utf-8") as fh:
        for rec in kept:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"{name}: {len(kept)} records")


def build(src):
    verified(src)

    recs = []
    for setting in ("dh", "ds"):
        for variant in ("base", "enhanced"):
            data = json.loads((src / f"injecagent_test_cases_{setting}_{variant}.json")
                              .read_text(encoding="utf-8"))
            for k, case in enumerate(data):
                recs.append({"id": f"injecagent-{setting}-{variant}-{k}",
                             "source": "injecagent", "variant": variant,
                             "label": "attack", "lang": "en",
                             "text": case["Tool Response"]})
                # The same tool output with the injection slot left empty: a
                # matched benign document for every attacked one.
                clean = case["Tool Response Template"].replace(PLACEHOLDER, "")
                recs.append({"id": f"injecagent-{setting}-clean-{k}",
                             "source": "injecagent", "variant": "clean",
                             "label": "benign", "lang": "en", "text": clean})
    write("injecagent.jsonl", recs)

    recs = []
    for split in ("train", "test"):
        for k, row in enumerate(rows(src / f"deepset_{split}.parquet")):
            recs.append({"id": f"deepset-{split}-{k}", "source": "deepset",
                         "variant": split,
                         "label": "attack" if row["label"] == 1 else "benign",
                         "lang": guess_lang(row["text"]), "text": row["text"]})
    write("deepset.jsonl", recs)

    recs = []
    for split in ("train", "validation", "test"):
        for k, row in enumerate(rows(src / f"lakera_{split}.parquet")):
            recs.append({"id": f"lakera-{split}-{k}", "source": "lakera",
                         "variant": split, "label": "attack", "lang": "en",
                         "text": row["text"]})
    write("lakera.jsonl", recs)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fetch", type=Path, metavar="DIR")
    ap.add_argument("--build", type=Path, metavar="DIR")
    args = ap.parse_args()
    if not (args.fetch or args.build):
        ap.error("use --fetch DIR, --build DIR, or both")
    if args.fetch:
        fetch(args.fetch)
    if args.build:
        build(args.build)


if __name__ == "__main__":
    main()
