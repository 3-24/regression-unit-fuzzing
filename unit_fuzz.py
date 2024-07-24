import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pandas as pd
import pathos
import rich
from tqdm import tqdm

from carve_common import parse_carve_filename, process_context
from config import (AFL_FUZZ, AFLCC, CARVING_LLVM, CROWN_HARNESS_GENERATOR,
                    CROWN_TC_GENERATOR, PIN, create_connection)
from project_base import Project
from utils import *
from utils import check_call


class Unit(Project):
    def __init__(self, name, version, function, tag=None):
        super().__init__(name, version, tag)
        self.function = function
        self.base_bin = self.bin

        self.preprocessed_file = find_preprocessed_file(self, function)

        if self.preprocessed_file is None:
            raise ValueError(
                f"Cannot find preprocessed file for {self.name} {self.version} {self.function}"
            )

        original_file = self.src_project_dir / self.preprocessed_file.with_suffix(".c")
        if not original_file.exists():
            # Search in self.src_project_dir recursively
            for f in self.src_project_dir.rglob("*.c"):
                if f.name == self.preprocessed_file.with_suffix(".c").name:
                    original_file = f
                    break
        assert original_file.exists()

        self.declaration = get_declaration(original_file, function)

        self.harness_src = (
            self.src_project_dir / f"{self.preprocessed_file}.{self.function}.driver.c"
        )

        self.bin = (
            self.src_project_dir / f"{self.preprocessed_file}.{self.function}.replay"
        )
        self.fuzzer_bin = (
            self.src_project_dir / f"{self.preprocessed_file}.{self.function}.fuzzer"
        )
        self.carver_bin = (
            self.src_project_dir / f"{self.preprocessed_file}.{self.function}.carver"
        )
        self.trace_bin = (
            self.src_project_dir / f"{self.preprocessed_file}.{self.function}.tracer"
        )

        self.fuzz_out_base = self.data_dir / "unit_fuzz" / f"{self.function}_out"

        self.fuzz_in_dir = self.out_dir / "fuzz_in"
        self.fuzz_out_dir = lambda i: self.fuzz_out_base / f"fuzz_out_{i}"

    def save_declaration(self):
        assert self.declaration is not None
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO function (project, function_name, declaration) Values (%s, %s, %s) ON CONFLICT DO NOTHING",
            (self.name, self.function, self.declaration),
        )
        conn.commit()
        cursor.close()
        conn.close()

    def generate_harness(self, null=True, length=2, ignore_exist=True, debug=False):
        if ignore_exist:
            if self.harness_src.exists():
                return

        self.fuzz_out_base.mkdir(parents=True, exist_ok=True)

        cmd = [
            CROWN_HARNESS_GENERATOR,
            "-i",
            self.src_project_dir / self.preprocessed_file,
            "-t",
            self.function,
            "-l",
            str(length),
        ]
        if null:
            cmd.extend(("-n", "1"))
        check_call(cmd, cwd=self.fuzz_out_base)

    def patch_preprocessed_file(self):
        preprocessed_file = self.src_project_dir / self.preprocessed_file

        rule = {
            "_Float32x": "float",
            "_Float64x": "double",
            "_Float128x": "long double",
            "_Float32": "float",
            "_Float64": "double",
            "_Float128": "long double",
        }
        rep = dict((re.escape(k), v) for k, v in rule.items())
        pattern = re.compile("|".join(rep.keys()))

        content = preprocessed_file.read_text()
        content = pattern.sub(lambda m: rep[re.escape(m.group(0))], content)

        preprocessed_file.write_text(content)

    def build_fuzzer(self, debug=False):
        env = {}
        # env["AFLCC"] = str(AFLCC)
        if self.sanitizer == "address":
            env["AFL_USE_ASAN"] = "1"
        elif self.sanitizer == "none":
            pass
        elif self.sanitizer == "undefined":
            env["AFL_USE_UBSAN"] = "1"
        else:
            assert False
        self.patch_preprocessed_file()

        env["AFL_LLVM_LAF_ALL"] = "1"

        with tempfile.TemporaryDirectory() as tmpdirname:
            env["TMPDIR"] = tmpdirname
            cmd = [
                AFLCC,
                self.harness_src,
                "-o",
                self.fuzzer_bin,
                "-g",
                "-O0",
                "-DSYM_USE_POINTER",
                "-DAFL",
                "-Wno-attributes",
                f"-I{CROWN_TC_GENERATOR}/include",
                f"-L{CROWN_TC_GENERATOR}/lib",
                "-lfuzz",
                "-lm",
            ] + self.fuzzer_libs

            check_call(cmd, env=env)

        # Init corpus directory
        shutil.rmtree(self.fuzz_in_dir, ignore_errors=True)
        self.fuzz_in_dir.mkdir(parents=True, exist_ok=True)

        # Add empty file to corpus directory
        (self.fuzz_in_dir / "input").write_text("input")

    def run_fuzzer(self, i, timeout):
        fuzz_out_dir = self.fuzz_out_dir(i)

        # Init output directory
        shutil.rmtree(fuzz_out_dir, ignore_errors=True)
        fuzz_out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            AFL_FUZZ,
            "-i",
            self.fuzz_in_dir,
            "-o",
            fuzz_out_dir,
            "-V",
            str(timeout),
            "--",
            self.fuzzer_bin,
            "@@",
        ]
        check_call(
            cmd, env={"AFL_NO_STARTUP_CALIBRATION": "1", "AFL_NO_UI": "1"}, quiet=True
        )

    def build_trace(self):
        # Make binary to get the stack trace
        self.patch_preprocessed_file()

        cmd = [
            "clang",
            self.harness_src,
            "-o",
            self.trace_bin,
            "-g",
            "-O0",
            "-DSYM_USE_POINTER",
            "-DAFL",
            "-Wno-attributes",
            f"-I{CROWN_TC_GENERATOR}/include",
            f"-L{CROWN_TC_GENERATOR}/lib",
            "-lfuzz",
            "-lm",
        ] + self.fuzzer_libs

        if self.sanitizer == "address":
            cmd.extend(["-fsanitize=address", "-fno-omit-frame-pointer"])
        elif self.sanitizer == "undefined":
            cmd.extend(["-fsanitize=undefined", "-fno-omit-frame-pointer"])
        else:
            assert False

        check_call(cmd, cwd=self.src_project_dir)

    def build_carving(self):
        env = os.environ.copy()

        # Remove existing files
        rm_cmd = [
            "rm",
            "-f",
            self.bin,
            self.carver_bin,
            f"{self.bin}.bc",
            f"{self.carver_bin}.bc",
        ]

        subprocess.check_call(rm_cmd, env=env)

        gclang_cmd = [
            "gclang",
            "-o",
            self.bin,
            self.harness_src,
            "-I",
            f"{CROWN_TC_GENERATOR}/include",
            "-L",
            f"{CROWN_TC_GENERATOR}/lib",
            "-lcrown-replay",
            "-Wno-attributes",
            "-g",
            "-O0",
        ] + self.fuzzer_libs

        subprocess.check_call(gclang_cmd, env=env)

        get_bc_cmd = ["get-bc", "-o", f"{self.bin}.bc", self.bin]

        subprocess.check_call(get_bc_cmd, env=env)

        # Write function name to tmpfile
        target = self.fuzz_out_base / "target.txt"
        target.write_text(self.function)

        opt_cmd = [
            "opt",
            "-enable-new-pm=0",
            "-load",
            f"{CARVING_LLVM}/lib/carve_model_pass.so",
            "--carve",
            f"--target={target}",
            "-crash",
            f"{self.bin}.bc",
            "-o",
            f"{self.carver_bin}.bc",
        ]

        subprocess.check_call(opt_cmd, env=env)

        compile_cmd = [
            "clang++",
            f"{self.carver_bin}.bc",
            "-o",
            self.carver_bin,
            "-L",
            f"{CARVING_LLVM}/lib",
            "-l:m_carver.a",
            "-I",
            f"{CROWN_TC_GENERATOR}/include",
            "-L",
            f"{CROWN_TC_GENERATOR}/lib",
            "-lcrown-replay",
        ] + self.fuzzer_libs

        subprocess.check_call(compile_cmd, env=env)

        harness_src_name = self.harness_src.name

        cleanup_cmd = ["rm", f".{harness_src_name}.o", f".{harness_src_name}.o.bc"]

        subprocess.check_call(cleanup_cmd, env=env, cwd=Path.cwd())

        assert Path(self.carver_bin).exists()

    def run_carving(self, i, pass_limit=100, timeout=None, multi=True, testcase=None):
        fuzz_out_dir = self.fuzz_out_base / f"fuzz_out_{i}"
        pass_testcase_dir = fuzz_out_dir / "default" / "queue"
        fail_testcase_dir = fuzz_out_dir / "default" / "crashes"

        def carve_and_postprocess(arg):
            is_crash, testcase = arg
            conn = create_connection()
            cursor = conn.cursor()

            with tempfile.TemporaryDirectory() as out_dir:
                cmd_carv = [
                    PIN,
                    "-t",
                    f"{CARVING_LLVM}/pintool/obj-intel64/MemoryTrackTool.so",
                    "--",
                    self.carver_bin,
                    testcase,
                    out_dir,
                ]
                try:
                    with tempfile.TemporaryDirectory() as run_dir:
                        run(
                            cmd_carv,
                            timeout=timeout,
                            cwd=run_dir,
                            quiet=True,
                            print=False,
                        )
                    for carve_file in Path(out_dir).glob(f"*"):
                        carve_name = carve_file.name
                        carved_function, call_idx = parse_carve_filename(carve_name)
                        if carved_function != self.function or call_idx != 1:
                            continue
                        content = carve_file.read_text()
                        content = process_context(content)

                        cursor.execute(
                            "INSERT INTO unit_carving (project, function_name, testcase, context, context_hash, is_crash, sanitizer_report, expr_index) Values (%s, %s, %s, %s, hashtextextended(%s, 0), %s, NULL, %s) ON CONFLICT DO NOTHING",
                            (
                                self.name,
                                self.function,
                                testcase.name,
                                content,
                                content,
                                is_crash,
                                i,
                            ),
                        )
                        break

                except subprocess.TimeoutExpired:
                    rich.print(f"[red]Timeout while carving {testcase}")
                except Exception:
                    rich.print(f"[red]Exception while carving {testcase}")

            conn.commit()
            cursor.close()
            conn.close()
            return

        # testcase in pass directory and fail directory
        if testcase is None:
            args = [(False, x) for x in pass_testcase_dir.glob("*")][:pass_limit] + [
                (True, x) for x in fail_testcase_dir.glob("*")
            ]
        else:
            args = testcase

        if multi:
            pool = pathos.multiprocessing.Pool()
            for _ in tqdm(
                pool.imap_unordered(carve_and_postprocess, args), total=len(args)
            ):
                pass
        else:
            for arg in tqdm(args):
                carve_and_postprocess(arg)


def get_top_k(name, version, tag="gnu", k=10, decl_save=False):
    targets_file = Path(f"data/{name}/target.txt")
    if targets_file.exists():
        targets = targets_file.read_text().split("\n")
        res = []
        for target in targets:
            if target == "":
                continue
            u = Unit(name, version, target, tag=tag)
            res.append(u)
            if decl_save:
                u.save_declaration()
        return res
    else:
        unit_ranking = pd.read_csv(f"data/{name}/unit_ranking.csv")

        res = []
        with open(targets_file, "w") as f:
            count = 0
            for i in range(len(unit_ranking)):
                func = unit_ranking["function"][i]
                try:
                    unit = Unit(name, version, func, tag=tag)
                    res.append(unit)
                    if decl_save:
                        unit.save_declaration()
                except ValueError:
                    continue

                f.write(func + "\n")
                count += 1
                if count >= k:
                    break
        return res


def count_fail_testcases(project, iterable):
    res = []
    for unit in iterable:
        count = len(list(unit.fail_testcases.iterdir()))
        res.append({"Function": unit.function, "# of crashes": count})

    df = pd.DataFrame(res)
    # plot
    plt = df.plot.barh(
        x="Function",
        y="# of crashes",
        rot=0,
        title=f"Unit Crashes of {project.name}",
        grid=True,
    )
    fig = plt.get_figure()
    fig.tight_layout()
    fig.savefig(project.data_dir / "count_crashes.png")
