import json
import os
from pathlib import Path

import psycopg2


def create_connection():
    username = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    host = os.environ.get("POSTGRES_HOST")
    return psycopg2.connect(user=username, password=password, host=host, port=5432)


# Path to bugoss-fuzz
CROWN_HARNESS_GENERATOR = (
    Path.cwd() / "tools" / "crown_harness_generator" / "crown_harness_generator"
)
CROWN_TC_GENERATOR = Path.cwd() / "tools" / "crown_tc_generator"
CARVING_LLVM = Path.cwd() / "tools" / "carving_llvm"
CROWNC = CROWN_TC_GENERATOR / "bin" / "crownc"
AFL_CROWNC = CROWN_TC_GENERATOR / "bin" / "afl-crownc"
RUN_CROWN = CROWN_TC_GENERATOR / "bin" / "run_crown"
LIBFUZZER_DRIVER = Path.cwd() / "libfuzzer" / "libfuzzer.a"
AFLCC = Path.cwd() / "tools" / "AFLplusplus" / "afl-clang-lto"
AFL_FUZZ = Path.cwd() / "tools" / "AFLplusplus" / "afl-fuzz"
PRINT_FUNCTION = Path.cwd() / "tools" / "print_function" / "lib"
PIN = CARVING_LLVM / "pin" / "pin"


def corpus_dir(project_name):
    return Path.cwd() / "data" / project_name / "corpus"


def list_projects():
    return list(map(lambda x: x["name"], json.load(open("project_config.json"))))
