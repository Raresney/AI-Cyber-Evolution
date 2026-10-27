# Paper — AISec @ CCS submission (skeleton)

`main.tex` is an ACM `acmart` (sigconf) skeleton for the generalization-ladder
paper. Abstract, introduction, method (`\S The Generalization Ladder`), setup,
results (three rung tables + scale ablation), discussion, and conclusion are in
place. Result tables hold the **real measured numbers** from `../results/*.json`;
`\todo{...}` markers flag prose and a figure still to write.

## Figure

`fig-ladder.pdf` (recall-up / precision-down vs rung, 3B vs 8B) is generated
from the results JSONs:

```bash
python ../experiments/plot_ladder.py   # writes paper/fig-ladder.{pdf,png}
```

## Build

Needs a TeX distribution with the ACM `acmart` class (TeX Live / MiKTeX ship it).

```bash
cd paper
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

Or `latexmk -pdf main.tex`.

## Provenance of the numbers

| Table | Source JSON (`../results/`) | Field |
| --- | --- | --- |
| Rung 1 | `lsass-detection.json`, `llm-detection{,-8b}.json`, `llm-fewshot-detection{,-8b}.json` | `holdout` |
| Rung 2 | `ladder-subtechnique.json`, `llm-subtechnique-*{,-8b}.json` | `overall` / `transfer` |
| Rung 3 | `ladder-technique.json`, `llm-technique-*{,-8b}.json` | `overall` / `transfer` |
| Scale | all `*-8b.json` vs their 3B counterparts | best recall + precision |

Regenerate everything: run the loaders in `../environment/` (re-pull OTRF data,
gitignored) then the scripts in `../experiments/`. See `../results/README.md`
for the full findings write-up the paper condenses.

## To do before submission

- Expand remaining `\todo{}` prose (intro tightening, extra co-evolution cites,
  signature-memorization detail). Related work and the figure are done.
- Verify the arXiv IDs in `references.bib`.
- Anonymize is on (`anonymous,review`); turn off for camera-ready and fill
  authors/affiliation.
- Add the repo URL once public-for-review.
