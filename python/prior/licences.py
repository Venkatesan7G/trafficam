"""Which public datasets head C may be trained on, and why.

Checked 2026-11-27 by reading each dataset's own pages (links below). The
trainer refuses any dataset that is not "allowed" here, and copies the entry
into the sidecar sources file next to the weights, so every knowledge pack
says what it was trained on and under which terms.

Rule used: trafficam is GPL-3.0 and its weights may be used commercially by
anyone, so a dataset whose terms forbid commercial use, or give no terms at
all, cannot be used for shipped weights.
"""

DATASETS = {
    "ctu13": {
        "name": "CTU-13 (Stratosphere Lab, CTU Prague)",
        "allowed": True,
        "licence": "CC BY 2.0",
        "terms_url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/README.html",
        "terms_quote": "The licence of the CTU-13 is CC-BY",
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2",
        "citation": "Garcia, Grill, Stiborek, Zunino. An empirical comparison of botnet detection methods. "
                    "Computers and Security 45 (2014) 100-123. doi:10.1016/j.cose.2014.05.011",
    },
    "unsw-nb15": {
        "name": "UNSW-NB15 (UNSW Canberra)",
        "allowed": False,
        "licence": "academic research only",
        "terms_url": "https://unsworks.unsw.edu.au/items/4dc0e35c-6196-4c9d-945a-c50b981e5955",
        "terms_quote": "Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in "
                       "perpetuity. Use for commercial purposes is strictly prohibited.",
        "why_not": "commercial use prohibited; GPL-3.0 weights can be used commercially. "
                   "(The project page says commercial use 'should be agreed by the authors': ask them in writing to change this.)",
    },
    "cic-ids2017": {
        "name": "CIC-IDS2017 / CSE-CIC-IDS2018 (UNB)",
        "allowed": False,
        "licence": "none stated",
        "terms_url": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "terms_quote": "publicly available for researchers. If you are using our dataset, you should cite our related paper",
        "why_not": "no licence, so no permission to redistribute derived weights; also known labelling errors",
    },
}


def check(dataset):
    """Return the registry entry, or raise if the dataset may not be used."""
    e = DATASETS.get(dataset)
    if e is None:
        raise SystemExit(f"dataset {dataset!r} is not in python/prior/licences.py; check its licence and add it first")
    if not e["allowed"]:
        raise SystemExit(f"dataset {dataset!r} may not be used for shipped weights: {e['why_not']}")
    return e
