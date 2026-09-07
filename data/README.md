# Dataset: LendingClub Loan Data (2007-2015)

This repository does **not** redistribute the dataset used by the manuscript's
evaluation section. You must obtain it yourself and place it locally.

## Dataset identity

- **Name (per manuscript, Sec. 6.1.1):** LendingClub Loan Data, 2007-2015.
- **Source URL (as cited in the manuscript):**
  `https://www.kaggle.com/datasets/adarshsng/lending-club-loan-data-csv`
- **Manuscript's stated scale:** "over two million loan records from 2007 to
  2015 ... After standard preprocessing ... approximately 890,000
  observations with 75 variables."

**As of this checkpoint, no LendingClub file has been located in this
environment** (checked the repository, the user's home directory, and common
data-cache locations). Nothing in `evaluation/` or `src/fairlend/data/`
assumes a specific raw filename, row count, or column count beyond what the
loader explicitly validates — see `docs/MANUSCRIPT_EVIDENCE_STATUS.md` for
what is and is not yet reproduced.

## This repository does not redistribute the data

Do not commit any LendingClub CSV (or any derived file containing its rows)
to this repository. `data/raw/`, `data/processed/`, and `data/cache/` are
`.gitignore`d except for `.gitkeep` placeholders.

## Expected local path

Place the raw CSV (as downloaded from the URL above, uncompressed) at:

```
data/raw/loan.csv
```

If your download uses a different filename (Kaggle's export is sometimes
named `loan.csv`, `accepted_2007_to_2018Q4.csv`, or similar depending on
which LendingClub release you pull), either rename it to `data/raw/loan.csv`
or pass the actual path explicitly — the loader never guesses a filename or
silently substitutes a different release.

## Exact preparation command

```bash
python evaluation/prepare_lendingclub.py \
    --input data/raw/loan.csv \
    --output data/processed/
```

This command:

1. computes and records the SHA-256 of the exact file at `--input`;
2. loads it and reports the actual raw row/column counts (it does **not**
   assume or force the manuscript's ~890,000-row figure -- see
   `docs/MANUSCRIPT_EVIDENCE_STATUS.md` for the comparison once a real file
   has been processed);
3. writes `results/evaluation/dataset_summary.json` and
   `results/metadata/dataset_manifest.json` recording the hash, row/column
   counts, and cleaning decisions actually applied;
4. writes the cleaned table to `data/processed/`.

## Verifying the file hash

After downloading, verify you and any collaborator are using the identical
file before trusting any comparison to manuscript figures:

```bash
sha256sum data/raw/loan.csv
```

`evaluation/prepare_lendingclub.py` records this same hash automatically in
`results/metadata/dataset_manifest.json`; compare it against that file
rather than re-deriving trust from the filename or row count alone, since
different LendingClub export vintages (e.g. different Kaggle re-uploads,
different end dates) can have different content while sharing a name.

## Repayment-outcome and proxy-feature configuration

The `loan_status` -> {positive, negative, excluded} mapping and the
synthetic protected-attribute configuration are **not** hidden in code --
see `configs/evaluation.yaml`, which is the single source of truth the
loader and downstream scripts read from.
