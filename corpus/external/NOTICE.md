# Third-party data

The files in this directory are derived from three public datasets. They were
converted to JSON Lines, deduplicated, and (for deepset) tagged with a guessed
language; the text itself is unchanged. `tools/build_corpus.py` rebuilds them
from the pinned upstream files and checks every sha256.

| file | upstream | revision | licence |
|---|---|---|---|
| `injecagent.jsonl` | [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), `data/test_cases_{dh,ds}_{base,enhanced}.json` | `f19c9f2c79a4` | MIT, see `LICENSE-InjecAgent.txt` |
| `deepset.jsonl` | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | `4f61ecb038e9` | Apache-2.0 per the card's top-level field (the card's `dataset_info` block also says CC BY 4.0); see `LICENSE-Apache-2.0.txt` |
| `lakera.jsonl` | [Lakera/gandalf_ignore_instructions](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | `04737b65e90a` | MIT, see `LICENSE-gandalf_ignore_instructions.txt` |

What each record means here:

- **InjecAgent**: `Tool Response` is a simulated tool output with an attacker
  instruction inserted (`label: attack`). `variant: base` is the instruction
  alone, `variant: enhanced` prefixes it with an explicit "ignore all previous
  instructions" sentence. `variant: clean` is the same tool output with the
  injection slot left empty (`label: benign`).
- **deepset**: `label` 1 becomes `attack`, 0 becomes `benign`. The `lang` field
  is a guess from function words (English or German), not upstream data.
- **Lakera**: prompts submitted to the Gandalf game and selected for their
  similarity to "ignore all previous instructions"; all are `attack`. Its card
  warns that a few may not be real injections.

Citation requested by Lakera: Pfister et al., *Gandalf the Red: Adaptive
Security for LLMs*, arXiv:2501.07927 (2025). InjecAgent: Zhan et al.,
*InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large
Language Model Agents*, Findings of ACL 2024.
