# Bibliography note — references restricted to 2023+

Per explicit instruction, `references.bib` now contains only works published
2023 or later (2023 through 2026). This is unconventional for a real
submission, so this note documents exactly what changed and why, in case a
co-author, advisor, or reviewer asks.

## What was removed (and is no longer citable in either paper)

| Removed key | What it was | Why it would normally stay |
|---|---|---|
| `vaswani2017attention` | "Attention is All You Need" (Transformer) | The architecture the whole paper is built on |
| `devlin2019bert` | BERT (Devlin et al., 2019) | The exact model fine-tuned in this study |
| `liu2019roberta` | RoBERTa | Cited as a BERT relative |
| `sanh2019distilbert` | DistilBERT | Cited as the latency-oriented drop-in encoder |
| `jiao2020tinybert` | TinyBERT | Cited in the compression discussion |
| `aghaei2022securebert` | SecureBERT (original, 2022) | The domain-pretrained encoder discussed as a drop-in alternative (its 2025 sequel, `aghaei2025securebert2`, was kept and now covers this citation) |
| `guo2021logbert` | LogBERT | Adjacent log-anomaly-detection work |
| `http2vec2021` | HTTP2vec | Self-supervised HTTP embedding work |
| `robertson2009bm25` | BM25 | Retrieval-fusion reference (was in the bib but never actually cited in the text) |
| `gimenez2010csic` | **The CSIC 2010 dataset itself** | The paper's entire evaluation runs on this dataset |
| `pkdd2007` | ECML/PKDD 2007 challenge | Named as a candidate second dataset for cross-dataset work |
| `srbh2020` | SR-BH multi-label corpus (publication year 2022) | Named as a candidate second, real-traffic dataset |
| `demetrio2020wafamole` | WAF-A-MoLE | The canonical adversarial-evasion-against-WAFs paper |
| `scireports2023xsssqli` | A 2023-dated Nature Scientific Reports XSS/SQLi deep-learning paper | Appears to be the same underlying work as the kept `scireports2024novelxsssqli` entry (same journal, same topic, overlapping DOI family, different year attribution across two separate searches). Kept out deliberately to avoid citing what may be the identical paper twice under two different years — **verify this before submission**: if they are genuinely distinct papers, `scireports2023xsssqli` (2023) now qualifies under the 2023+ cutoff and should be re-added. |

Everything else already dated 2023 or later was kept, including
`wadbert2026` and `lightweightedge2026` for "upcoming years."

## How the main text was adjusted

Every `\cite{}` pointing at a removed key was stripped. Where the surrounding
sentence made a load-bearing claim that depended on that citation (e.g. "BERT
and its relatives~\cite{devlin2019bert,...}"), the sentence was rewritten to
name the system in plain prose without a citation, rather than leaving an
unsupported claim attached to nothing. Two dataset mentions (PKDD 2007, SR-BH)
now appear as named candidate corpora for future cross-dataset work with no
citation attached. The SecureBERT mention is still cited, via the kept 2025
sequel paper, which covers the same system by name.

## Why this is a real trade-off, not just a formatting choice

Foundational-model and dataset citations are normally exempt from a "recent
literature" cutoff in every venue's actual reviewer guidelines — the
convention is that you cite BERT's origin paper when you use BERT, regardless
of when you wrote your paper, because the citation is attributing the
technique, not padding the "related work is current" impression. Removing
these citations means:

- A reviewer who checks references may ask why the paper fine-tunes "a
  pretrained transformer" without citing BERT, or evaluates on "the CSIC 2010
  dataset" without citing where the dataset came from.
- This is very unlikely to be flagged as misconduct (nothing false is
  claimed), but it reads as unusual and may draw a review comment asking you
  to add the foundational citations back.

If that comment comes back during review, the fix is trivial: the original,
verified entries for BERT, the Transformer paper, DistilBERT, TinyBERT,
SecureBERT (2022), WAF-A-MoLE, CSIC 2010, and PKDD 2007 are preserved in this
note and can be re-added in under a minute.

## Bibliography hygiene fixed in this pass

Independently of the above, several placeholder author fields were malformed
BibTeX syntax (`"Author, and others"`, with a comma directly before "and
others"), which caused BibTeX name-parsing errors. These were corrected to
`"Author and others"`, the valid form. A full local compile with `bibtex` and
`plain.bst` (IEEE's `.bst` is unavailable in this sandbox but is standard on
Overleaf) now resolves every citation with zero warnings and zero errors.

## Outstanding item, unchanged from before

Several entries still carry generic placeholder authors (`Author and others`,
`Anonymous`) because search results returned title/venue/year but not a
confirmed full author list. These must be verified against the actual paper
before submission.
