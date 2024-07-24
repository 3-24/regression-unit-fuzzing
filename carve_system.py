import random
import subprocess
import tempfile
from pathlib import Path

import pandas as pd
import pathos
import rich
from tqdm import tqdm

from carve_common import parse_carve_filename, process_context
from config import (CARVING_LLVM, LIBFUZZER_DRIVER, PIN, corpus_dir,
                    create_connection)
from project_base import Project
from utils import check_call, get_cmd


class SystemCarvingTestCase:
    def __init__(self, name, project):
        self.name = name
        self.project = project

    def run(self, timeout=None):
        with tempfile.TemporaryDirectory() as run_dir:
            cmd = [self.project.base_bin, self.name]
            try:
                subprocess.run(
                    cmd,
                    timeout=timeout,
                    cwd=run_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired:
                rich.print(f"[red]Timeout while running {self.name}[/red]")

    def run_carving(self, timeout=None, raw=False, save=False):
        out_dir = tempfile.TemporaryDirectory()
        table_name = "system_carving_raw" if raw else "system_carving"

        with tempfile.TemporaryDirectory() as run_dir:
            cmd = [
                PIN,
                "-t",
                f"{CARVING_LLVM}/pintool/obj-intel64/MemoryTrackTool.so",
                "--",
                self.project.base_bin,
                self.name,
                Path(out_dir.name),
            ]
            try:
                subprocess.run(
                    cmd,
                    timeout=timeout,
                    cwd=run_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if save:
                    for carve_file in Path(out_dir).glob("*"):
                        carve_name = carve_file.name
                        carved_function, _ = parse_carve_filename(carve_name)
                        content = carve_file.read_text()
                        content = process_context(content)
                        if content is None:
                            rich.print(
                                f"[red]Exception while carving {self.name}\n{carve_file}[/red]"
                            )
                            continue

                        conn = create_connection()
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO {} (project, function_name, context, context_hash) values (%s, %s, %s, hashtextextended(%s, 0)) ON CONFLICT DO NOTHING".format(
                                table_name
                            ),
                            (self.project.name, carved_function, content, content),
                        )
                        conn.commit()
                        cursor.close()
                        conn.close()

            except subprocess.TimeoutExpired:
                rich.print(f"[red]Timeout while carving {self.name}[/red]")

        out_dir.cleanup()


class SystemCarving(Project):
    def __init__(self, name, version, tag=None):
        super().__init__(name, version, tag)
        self.base_bin = self.bin
        self.bin = self.base_bin.with_suffix(".carve")

    def build(self, debug=False):
        assert self.base_bin.exists()
        assert CARVING_LLVM.exists()
        target = Path.cwd() / "data" / self.name / "target.txt"
        assert target.exists()

        get_bc_cmd = ["get-bc", "-o", f"{self.base_bin}.bc", self.base_bin]
        opt_cmd = [
            "opt",
            "-enable-new-pm=0",
            "-load",
            f"{CARVING_LLVM}/lib/carve_model_pass.so",
            "--carve",
            f"--target={target}",
            f"{self.base_bin}.bc",
            "-o",
            f"{self.bin}.bc",
        ]
        comp_cmd = [
            "clang++",
            f"{self.bin}.bc",
            "-o",
            self.bin,
            "-L",
            f"{CARVING_LLVM}/lib",
            "-l:m_carver.a",
            LIBFUZZER_DRIVER,
        ] + self.fuzzer_libs
        check_call(get_bc_cmd, cwd=self.out_dir)
        check_call(opt_cmd, cwd=self.out_dir)
        check_call(comp_cmd, cwd=self.out_dir)

    def run(
        self,
        limit=20000,
        timeout=None,
        debug=False,
        target=None,
        parallel=True,
        raw=False,
    ):
        assert self.bin.exists()
        if target is None:
            corpus = list(corpus_dir(self.name).iterdir())
            if limit is not None and len(corpus) > limit:
                corpus = random.sample(corpus, limit)
        else:
            corpus = target

        def carve_and_postprocess(testcase):
            if not debug:
                _out_dir = tempfile.TemporaryDirectory()
                out_dir = Path(_out_dir.name)
            else:
                out_dir = self.out_dir / "carve-system" / testcase.name
                out_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory() as run_dir:
                try:
                    cmd = [
                        PIN,
                        "-t",
                        f"{CARVING_LLVM}/pintool/obj-intel64/MemoryTrackTool.so",
                        "--",
                        self.bin,
                        testcase,
                        out_dir,
                    ]
                    if debug:
                        rich.print(f"[green]{get_cmd(cmd)}[/green]")
                        subprocess.run(cmd, timeout=timeout, cwd=run_dir)
                    else:
                        subprocess.run(
                            cmd,
                            timeout=timeout,
                            cwd=run_dir,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    for carve_file in Path(out_dir).glob("*"):
                        carve_name = carve_file.name
                        carved_function, _ = parse_carve_filename(carve_name)
                        content = carve_file.read_text()

                        if not raw:
                            content = process_context(content)
                            if content is None:
                                rich.print(
                                    f"[red]Exception while carving {testcase}\n{carve_file}[/red]"
                                )
                                if debug:
                                    input()
                                continue

                        conn = create_connection()
                        cursor = conn.cursor()
                        if debug:
                            (out_dir / f"{carve_name}.processed").write_text(content)
                        cursor.execute(
                            "INSERT INTO {} (project, function_name, context, context_hash) values (%s, %s, %s, hashtextextended(%s, 0)) ON CONFLICT DO NOTHING".format(
                                "system_carving_raw" if raw else "system_carving"
                            ),
                            (self.name, carved_function, content, content),
                        )
                        conn.commit()
                        cursor.close()
                        conn.close()
                except subprocess.TimeoutExpired:
                    rich.print(f"[red]Timeout while carving {testcase}")
            if not debug:
                _out_dir.cleanup()

        if parallel:
            with pathos.helpers.mp.Pool() as pool:
                for _ in tqdm(
                    pool.imap_unordered(carve_and_postprocess, corpus),
                    total=len(corpus),
                ):
                    pass
        else:
            for testcase in tqdm(corpus):
                carve_and_postprocess(testcase)

    def get(self, function_name):
        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT context FROM system_carving WHERE project = %s AND function_name = %s",
            (self.name, function_name),
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows

    def count_system_testcases(self, units):
        res = []
        for u in units:
            function_name = u.function
            res.append(
                {
                    "Function": function_name,
                    "# of carved testcases": len(self.get(function_name)),
                }
            )

        df = pd.DataFrame(res)
        plt = df.plot.barh(
            x="Function",
            y="# of carved testcases",
            title=f"# of system-level carved objects for each units in {self.name}",
            grid=True,
        )
        fig = plt.get_figure()
        fig.tight_layout()
        fig.savefig(self.data_dir / "count_system_testcases.png")
