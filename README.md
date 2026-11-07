# injection-guard

A small prompt-injection guard for the hooks of coding agents (Claude Code,
Codex). One Python file, standard library only, no network. It has been
measured on public datasets and on three months of real agent sessions, and it
is honest about what it misses.

It does two things:

- **After every tool call** (`PostToolUse`), it scans what came back (a web
  page, a file, a command's output, an MCP response) for text that tries to
  pass itself off as an instruction, and tells the agent. It never blocks.
- **Before every shell command** (`PreToolUse`), it blocks `curl ... | sh` and
  its variants, the step where fetched content becomes code that runs. It
  parses shell quoting, so a note that merely *mentions* that command is not
  blocked.

## What it does not catch

Read this before relying on it.

- **Paraphrase.** These are regular expressions. An injection that does not
  use the usual wording goes through: on InjecAgent, the guard flags 1.6 % of
  the attacker instructions on their own, and 100 % of the same instructions
  once prefixed with an explicit "ignore all previous instructions".
- **Other languages.** The patterns are English only. On the German half of
  deepset/prompt-injections it detects nothing.
- **Quoted injections.** A match inside a short quotation, inline code or a
  code block is treated as a citation: logged, not shown (see below). An
  attacker who knows this rule can quote the injection. On the Lakera dataset
  this rule costs 7 prompts out of 1,000.
- **Everything after the warning.** The post-tool check only informs the
  agent, which then decides what to do. The only thing actually stopped is
  piping a download into a shell.

It is an alarm for naive injections, not a wall. It complements, and does not
replace, sandboxing, least-privilege credentials and asking the human before
side effects.

## Measurements

Everything below is reproduced by `python3 evaluate.py`. "Before" is the
version this repository started from, and "after" is this one.

**Public datasets** (`corpus/external`, see `corpus/external/NOTICE.md`): share
of documents that produce at least one alert shown to the agent.

| documents | count | before | after |
|---|---:|---:|---:|
| InjecAgent tool outputs, injection prefixed with "ignore previous instructions" | 1,054 | 100 % | 100 % |
| InjecAgent tool outputs, attacker instruction alone | 1,054 | 0 % | 1.6 % |
| Lakera Gandalf prompts, held-out test split | 112 | 41.1 % | 45.5 % |
| deepset injections, English | 174 | 4.0 % | 4.0 % |
| deepset injections, German | 89 | 0 % | 0 % |
| deepset benign prompts | 399 | 0.5 % | 0 % |
| InjecAgent tool outputs without the injection | 17 | 0 % | 0 % |
| hand-written regressions of past false alarms | 20 | 15 | 4 |
| this repository's own source and docs | 6 | 2 | 0 |

**Real use.** The guard was replayed on every tool output of one person's
Claude Code and Codex sessions from 14 August to 7 November 2026, about
86,400 outputs. That data stays private. Only these counts are published.

| | before | after |
|---|---:|---:|
| alerts shown to the agent | 323 | 53 |
| of which on 7 November, when attack datasets were printed on purpose | 48 | 37 |
| over the 85 days before, per day | 3.2 | 0.19 |
| real injections found among them | 0 | 0 |

"Real injections found" comes from reading the alerts: the rare patterns in
full, the frequent ones by sampling and by grouping them by cause. Before the
changes, most alerts came from ordinary code and documentation: `process.env`
and `.env.example`, curl commands in API references, curl's `-D` option, HTML
login forms, model chat templates and emoji. The high-severity ones came from
notes and articles that quote injections, and from the guard's own test
output. Over the 85 days before the measurement, 16 alerts remain.

Known false alarms that remain: documentation that tells a human to "enter
the password" (the largest group), plain-text instructions to `cat` a secret
file, a README that says to run a script before going on, and fine-tuning
templates with an `### Instruction:` heading.

## Install

It needs Python 3.10 or later and nothing else.

```bash
python3 install.py
```

It copies `injection_guard.py` to `~/.local/share/injection-guard/` and points
the hook file of each agent it finds (`~/.claude/hooks`, `~/.codex/hooks`) at
that one copy with a symlink, keeping any file it replaces as `*.bak-DATE`.
One copy means a fix cannot reach one agent and miss the other.
`python3 install.py --check` verifies that every hook runs that copy and that
it matches the checkout.

It never edits settings. `python3 install.py --config` prints the two hook
entries to add to `~/.claude/settings.json` (and to `~/.codex/hooks.json`):
`PreToolUse` on `Bash`, `PostToolUse` on `WebFetch|WebSearch|Read|Grep|Bash|Task|mcp__.*`.

To switch it off for one command: `CLAUDE_INJECTION_GUARD=off`.

## How it decides

Each finding has a severity:

- **high**: wording with practically no legitimate use in fetched content
  (`override-instructions`, `identity-reassign`, `fake-authority`,
  `conceal-from-user`, `chat-delimiter`, hidden tag characters).
- **medium**: suspicious in context (`exfiltration`, `credential-bait`,
  `tool-coercion`, bidirectional overrides, long runs of zero-width
  characters).
- **low**: the match is a citation, or a few stray zero-width characters.
  Logged, never shown.

A match is a **citation** when it sits inside inline code, a fenced block,
typographic quotes, or straight double quotes that follow words in a
sentence, and the quoted span is at most 200 characters. A match next to
regular-expression syntax is a citation too. Quotes that open a value (`"key": "..."`, a
list, a function call) and long quoted strings are content, not citations,
so injections inside JSON and MCP responses are still reported.

Invisible characters are removed before matching, so a zero-width space in
the middle of a word does not hide it. Emoji joiners and byte-order marks
are ignored.

A finding is shown **once per session**. Repeats are logged, not shown.

The log, `~/.claude/hooks/injection-guard.jsonl`, keeps one JSON line per
event with a short excerpt of each finding, **redacted** first (assignments
of keys and passwords, known token prefixes, JWTs, long opaque strings).
`python3 tools/audit_log.py` summarises it, and `--list` prints the excerpts
so that each alert can be judged as real or false.

## Prior art

Other tools address the same problem with trained classifiers or hosted
services, and detect paraphrases this guard cannot:

- [Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
  (Meta): small classifier models, under the Llama 4 Community License.
- [LLM Guard](https://github.com/protectai/llm-guard) (Protect AI, MIT): input
  and output scanners for LLM applications, including a prompt-injection
  model.
- [Prompt Shields](https://learn.microsoft.com/azure/ai-services/content-safety/concepts/jailbreak-detection)
  (Azure AI Content Safety) and [Lakera Guard](https://www.lakera.ai/): hosted
  APIs. Prompt Shields has a mode for documents, which covers the indirect
  case.

What this one offers instead: no model, no dependency, no network call, a
few milliseconds per tool output, rules you can read in one file, and a hook
interface made for coding agents, with a shell-aware block on `curl | sh`.

## Development

```bash
python3 -m unittest discover -s tests   # blocking, patterns, hook, install, corpus bar
python3 evaluate.py                     # detection and false alarms, per group and pattern
python3 evaluate.py --guard OLD.py      # the same numbers for another version
python3 evaluate.py --transcripts ~/.claude/projects ~/.codex/sessions --samples 5
```

The rule: **no change to a pattern without the numbers before and after.**
`tests/test_corpus.py` holds the current numbers as thresholds, so a change
that lowers detection or adds false alarms fails until the threshold is moved
on purpose. Every alternative of every pattern has a test case that must
match: three of them could never match anything until November 2026, and
nothing had noticed.

When you tune a pattern, read only the `train` splits and keep the `test`
splits as the held-out measure.

## License

MIT, see `LICENSE`. The datasets in `corpus/external` keep their own licences
(MIT and Apache-2.0), listed in `corpus/external/NOTICE.md`.
