# Regression Unit Fuzzing

This is a framework for applying regression unit fuzzing on several C subjects.

## Installation
```bash
python -m venv .venv
source .venv /bin/activate
pip install -r requirements.txt
```

Also, we assume that
- gllvm
- CIL
- crown_harness_generator
- crown_tc_generator
are installed in ./tools.

## How to use

You can simply type help command to see its usage.
```
python helper.py --help
```