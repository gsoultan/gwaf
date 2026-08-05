# Knowledge Tooling

Three layers, following the gateon convention.

## Serena — persistent memories
`.serena/memories/` (this directory). Cross-session architectural context.

| Memory | Read it when |
|---|---|
| `core` | Orienting: what gwaf is, package map, scope line |
| `decisions` | **Before proposing an optimization** — several are already rejected with measurements |
| `measured_results` | Quoting numbers (but re-run them; never quote from memory) |
| `working_agreements` | How to work here: instruments first, premise-testing, fuzz requirements |
| `boundaries` | Scope questions: what belongs in gwaf vs the embedder |
| `gateon_adoption` | Anything touching the first adopter |

## Graphify — code graph
`graphify-out/` — 804 nodes, 1644 edges, 33 communities.

```bash
graphify update .              # rebuild after code changes (no LLM, no cost)
graphify query "how does the prefilter work"
graphify explain "Automaton"
graphify path "WAF" "Automaton"
graphify affected "Ruleset"    # reverse traversal: what breaks if this changes
```

**Check freshness**: `GRAPH_REPORT.md` records the commit it was built from.

## Obsidian — the vault
`~/Documents/ObsidianVault/gwaf` (837 notes + canvas).

- `000 gwaf — START HERE.md` is the map of content.
- `Memories/` and `Docs/` are **symlinks** into the repo, so they are always
  current. Only the graph export needs regenerating.

```bash
rtk graphify export obsidian --dir ~/Documents/ObsidianVault/gwaf
```

## Workflow
1. **Before a full file read**, check the graph or the memories. That is the
   whole point of having them.
2. **After significant architectural change**, run `graphify update .` and
   re-export.
3. **After a decision that cost real work** — especially a rejection — write it
   into `decisions`. The negative results are the most valuable notes here.
