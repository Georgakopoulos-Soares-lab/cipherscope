# JCEN submission package — CipherScope

Journal of Cryptographic Engineering (Springer, journal 13389).
Built 2026-11-19 from the `manuscript` branch tip (`c5274e8`, 2026-11-17),
source file `paper/manuscript-revised.tex`.

Portal: <https://submission.springernature.com/> — submission
`1efb1d2e-8135-46bf-8ad9-33c42d82e27e`, currently on the **Files** step.

---

## 1. What to upload

On the **Files** step, under **Manuscript file**, upload the single zip:

    paper/submission-jcen/cipherscope-jcen-submission.zip   (339 KB)

The portal accepts a `.zip` for LaTeX submissions and compiles it into a review
PDF. The zip contains:

| File | What it is |
|---|---|
| `manuscript.tex` | the manuscript, Springer `sn-jnl` class |
| `manuscript.bbl` | pre-built bibliography, so it compiles without BibTeX |
| `references.bib` | bibliography source |
| `sn-jnl.cls` | Springer Nature class file (official, v3.1 Dec 2024) |
| `sn-basic.bst` | Springer Nature basic reference style |
| `Fig1.pdf`–`Fig4.pdf` | the four figures, vector PDF, fonts embedded |
| `manuscript.pdf` | compiled output, 16 pages |

This matches the guideline: *"The submission should include the original source
(including all style files and figures) and a PDF version of the compiled
output."*

Figures and tables do **not** need separate upload at initial submission. Leave
the *Figures and tables* and *Supplementary material* sections empty.

---

## 2. Three things you must fill in first

These are marked `\todo{...}` in `manuscript.tex` and **render in red in the
PDF**, so they cannot be missed. Fill them in, rebuild, and re-zip (see §6).

1. **Funding** (`manuscript.tex` line ~1091) — mandatory. Grant numbers, and
   funder names written out in full. If there was none, the standard wording is
   in the TODO text.
2. **Author contribution** (line ~1132) — mandatory. A draft sentence is in the
   TODO text; edit it to match reality.
3. **Acknowledgements** (line ~1072) — optional. The repo has TACC/Lonestar6
   launchers (`tacc/`, `ls6_env.sh`), so if an allocation supported the cluster
   lanes it belongs here. Delete the section if not applicable.

Optional, if you have them: `\orgdiv{...}` per affiliation, co-author emails,
and 16-digit ORCIDs — see the comment above the author block.

---

## 3. Declarations to enter in the portal as well

JCEN: *"Author Contribution information and Competing Interest information must
be provided at submission via the submission interface. Only the information
submitted via the interface will be used in the final published version."*

So the same text goes in **two** places — the manuscript and the portal form:

- **Competing interests** — already written into the manuscript as: *the authors
  declare that they have no competing interests, financial or non-financial,
  that are directly or indirectly related to the work submitted for
  publication.* Copy this into the portal.
- **Author contributions** — whatever you write for item 2 above.

---

## 4. What was changed from `manuscript-revised.tex`

Nothing in the argument, the results, or the prose was touched. The changes are:

**Format (ACM → Springer).** The source was `acmart` `sigconf`. It is now
`\documentclass[pdflatex,sn-basic,Numbered,iicol]{sn-jnl}` — Springer's own
template with the `[iicol]` two-column option the journal recommends, and
`Numbered` for the square-bracket numeric citations JCEN requires.

**Added, because the journal requires them.**
- 6 keywords (JCEN asks for 4–6).
- A `Statements and Declarations` section: funding, competing interests, ethics,
  consent, data availability, materials availability, code availability, author
  contribution.
- A Data Availability Statement pointing at
  <https://github.com/Georgakopoulos-Soares-lab/cipherscope>, which is mandatory
  for original research.

**Mechanical.**
- Figures renamed `teaser/ablation/impact/overhead.pdf` → `Fig1`–`Fig4.pdf` per
  Springer's *"Name your figure files with Fig and the figure number"*, and moved
  to the top level of the zip.
- `\S\ref{...}` → `Sect.~\ref{...}` (26 places), Springer house style.
- Table 1 changed from a one-column to a full-width float. In the narrower
  Springer column it overflowed by 71 pt; full width fixes it and the table
  reads better.
- Abstract reflowed to a single paragraph. Wording unchanged — 236 words, inside
  the 150–250 range.

**Bibliography — the one substantive fix.** Eight entries still had TODO
placeholder author lists (`{Rotom authors}`, `{HEIR authors}`,
`{CryptOracle authors}`, `{HERTA authors}`, `{FHE-Agent authors}`,
`{Safety-centric analysis authors}`, `{Cross-platform benchmarking authors}`,
and two `and others`). All are now real author lists, verified against arXiv,
the USENIX program, SciTePress and Crossref. Three had the **wrong title**:

| Key | Was | Actually |
|---|---|---|
| `rotom2026` | *Rotom: Automatic Layout and Vectorization for Homomorphic Encryption* | *Bridging Usability and Performance: A Tensor Compiler for Autovectorizing Homomorphic Encryption* — Chen, Brown, Zheng, USENIX Sec 2026, pp. 141–160 |
| `cryptoracle2025` | *A Benchmark Suite and Performance/Energy Prediction Framework for OpenFHE* | *CryptOracle: A Modular Framework to Characterize Fully Homomorphic Encryption* — arXiv:2510.03565 |
| `herta2026` | *HERTA: Metamorphic Testing of Fully Homomorphic Encryption Frameworks* | *Detecting and Understanding Vulnerabilities in Fully Homomorphic Encryption Frameworks* — Peng et al., arXiv:2606.22519 |

Your prose describing each of these is still accurate — HERTA really is the tool
in that paper and really does use metamorphic testing; Rotom really does derive
packing layouts — so no body text needed changing. Only the reference entries
were wrong.

All page ranges and DOIs were confirmed against Crossref. DOIs render as full
`https://doi.org/...` links, as JCEN asks.

---

## 5. Requirements checked

| Requirement | Status |
|---|---|
| LaTeX source + compiled PDF | ✅ both in the zip |
| Springer template, `[iicol]` | ✅ `sn-jnl` v3.1 |
| Abstract 150–250 words | ✅ 236 |
| 4–6 keywords | ✅ 6 |
| Numbered `[n]` citations | ✅ `Numbered` option |
| Decimal headings, ≤3 levels | ✅ max 2 levels used |
| Corresponding author + email | ✅ Provatas, kap4722@eid.utexas.edu |
| Competing interests | ✅ in manuscript — also enter in portal |
| Data availability statement | ✅ GitHub |
| Figures named `FigN` | ✅ Fig1–Fig4 |
| Figure captions in the text file | ✅ not baked into the images |
| Fonts embedded in figures | ✅ verified with `pdffonts` |
| Build clean | ✅ 0 undefined refs, 0 overfull boxes, 16 pages |
| Funding statement | ❌ **TODO** |
| Author contributions | ❌ **TODO** |
| ORCIDs | ⚠️ not supplied (optional) |

Review is **single-blind**, so author names stay in the manuscript — no
anonymised version is needed.

Two notes on figures, neither a blocker. Springer says EPS is *preferred* for
vector art; the figures are vector PDF instead, because the `pdflatex` class
option expects PDF and PDF keeps the embedded fonts intact. Springer's own
template ships that way. Second, Springer asks for Helvetica or Arial lettering
in figures; yours use the matplotlib default. Neither is worth regenerating for
initial review — production will raise it if they care.

---

## 6. Rebuilding after you edit

```bash
cd paper/submission-jcen
tectonic -X compile manuscript.tex
rm -f manuscript.aux manuscript.log manuscript.out manuscript.blg manuscript.xdv
rm -f cipherscope-jcen-submission.zip
zip -X cipherscope-jcen-submission.zip manuscript.tex manuscript.bbl \
  references.bib sn-jnl.cls sn-basic.bst Fig1.pdf Fig2.pdf Fig3.pdf Fig4.pdf \
  manuscript.pdf
```

---

## 7. Remaining portal steps

After **Files**: *Details* (title, abstract, keywords — copy from the
manuscript), *Authors* (all three, Provatas as corresponding, affiliations and
ORCIDs), *Declarations* (§3 above), then *Review* and submit.
