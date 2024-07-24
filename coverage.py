import glob
import os
import random
import subprocess
from collections import Counter
from pathlib import Path

import pandas as pd
import pathos
import rich
from tqdm import tqdm

from config import LIBFUZZER_DRIVER, corpus_dir
from project_base import Project
from utils import get_cmd

BB_COV_DIR = ""  # TODO


class Coverage(Project):
    def __init__(self, name, version, tag=None):
        super().__init__(name, version, tag)
        self.base_bin = self.bin
        self.bin = self.base_bin.with_suffix(".cov")

    def build(self):
        assert self.base_bin.exists()
        env = os.environ.copy()
        get_bc_cmd = ["get-bc", "-o", f"{self.base_bin}.bc", self.base_bin]
        opt_cmd = [
            "opt",
            "-enable-new-pm=0",
            "-load",
            f"{BB_COV_DIR}/lib/bb_cov_pass.so",
            "--bbcov",
            f"{self.base_bin}.bc",
            "-o",
            f"{self.bin}.bc",
        ]
        compile_cmd = [
            "clang++",
            f"{self.bin}.bc",
            "-o",
            self.bin,
            "-L",
            f"{BB_COV_DIR}/lib",
            "-l:bb_cov_rt.a",
            LIBFUZZER_DRIVER,
        ] + self.libs

        rich.print(f"[green]{get_cmd(get_bc_cmd)}")

        subprocess.check_call(get_bc_cmd, env=env)
        subprocess.check_call(opt_cmd, env=env)
        subprocess.check_call(compile_cmd, env=env)

    def run(self, testcase, timeout):
        try:
            # Remove all .cov files recursively in the directory `src_project_dir`
            subprocess.run(
                ["find", ".", "-name", "*.cov", "-delete"],
                cwd=self.src_project_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [self.bin, testcase],
                timeout=timeout,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            return 0
        except subprocess.TimeoutExpired:
            rich.print(f"[red]Test case {testcase.name} timed out")
            return 1


def parse_cov_file(cov_file):
    result = {}

    cur_func = None

    with open(cov_file, "r") as f:
        for line in f:
            if line == "":
                continue

            line = line.strip()
            if line[0] == "F":
                line = line[2:]
                last_space = line.rfind(" ")
                covered = line[last_space + 1 :]
                line = line[:last_space]
                last_space = line.rfind(" ")
                bb_count = line[last_space + 1 :]
                cur_func = line[:last_space]
                result[cur_func] = [False] * int(bb_count)
            else:
                _, bb_index, covered = line.split(" ")
                if covered != "0" and covered != "1":
                    raise Exception("Invalid coverage file")
                result[cur_func][int(bb_index)] = covered == "1"

    return result


def parse_cov_files(cov_dir):
    result = {}
    cov_files = glob.glob(f"{cov_dir}/**/*.cov", recursive=True)
    if len(cov_files) == 0:
        rich.print(f"[red]No coverage file found in {cov_dir}")
        return None
    for cov_file in cov_files:
        cov_file_rel = cov_file[len(str(cov_dir)) + 1 :]
        result[cov_file_rel] = parse_cov_file(cov_file)
        # remove parsed file
        os.remove(cov_file)
    return result


def run_and_compare(before_conf, after_conf, testcase, timeout):
    def run_single(conf):
        # todo
        return_code = conf.run(testcase, timeout)
        if return_code:
            return None

        cov = parse_cov_files(conf.src_project_dir)
        if cov is None:
            return None

        return cov

    before_cov, after_cov = pathos.multiprocessing.ProcessPool(2).map(
        run_single, [before_conf, after_conf]
    )

    res = []
    if before_cov is None or after_cov is None:
        return res

    for filename in after_cov:
        if filename not in before_cov:
            for function_name in after_cov[filename]:
                res.append((filename, function_name))
            # rich.print(f"[red]File {filename} not found in before coverage")
            continue

        for function_name in after_cov[filename]:
            if (function_name not in before_cov[filename]) or (
                len(after_cov[filename][function_name])
                != len(before_cov[filename][function_name])
            ):
                res.append((filename, function_name))
                # rich.print(f"[red]Function {function_name} has different number of basic blocks")

            elif (
                after_cov[filename][function_name]
                != before_cov[filename][function_name]
            ):
                res.append((filename, function_name))
                # rich.print(f"[red]Function {function_name} has different basic block coverage")

    return res


def run_and_compare_all(before_conf, after_conf, limit=None, timeout=None):

    corpus = list(corpus_dir(before_conf.name).iterdir())

    if limit is None:
        corpus_limit = len(list(corpus))
    else:
        corpus_limit = limit

    corpus = random.sample(corpus, corpus_limit)
    counter = Counter()

    for testcase in tqdm(corpus):
        res = run_and_compare(before_conf, after_conf, testcase, timeout)
        counter.update(res)

    filename, func = zip(*counter.keys())
    count = counter.values()

    # Covert it to dataframe
    df = pd.DataFrame({"filename": filename, "function": func, "count": count})
    df.sort_values(by=["count"], ascending=False, inplace=True)

    out_name = Path.cwd() / "data" / before_conf.name / "coverage_diff.csv"

    out_name.parent.mkdir(parents=True, exist_ok=True)

    # Save as csv
    df.to_csv(out_name, index=False)
