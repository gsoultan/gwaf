# The 50k real-attack corpus: how to run it, and how to read a miss

Built 2026-08-16. `test/attackgen/generate.py` + `test/attackgen/runner_test.go`.
The generated .jsonl files are gitignored; the generator and runner are the
artifact.

```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /tmp/nuclei-templates
python3 test/headtohead/extract_corpus.py /tmp/nuclei-templates/http > /tmp/corpus.json
git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/crs

python3 test/attackgen/generate.py --n 50000 \
  --out test/attackgen/attacks.jsonl --benign test/attackgen/benign.jsonl \
  --extra /tmp/seeds_serverside.json /tmp/seeds_web.json

A=$PWD/test/attackgen
ATTACK_CORPUS=$A/attacks.jsonl BENIGN_CORPUS=$A/benign.jsonl \
  MISS_OUT=$A/misses.jsonl go test -run 'TestAttackCorpus|TestBenignNoFalse' -v ./test/attackgen/
```

Sources: nuclei-templates (real CVE exploit requests), the CRS regression suite,
and ~1560 curated real payloads across sqli