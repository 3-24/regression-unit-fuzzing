import json
import shutil
import subprocess
from pathlib import Path

import pathos.multiprocessing as mp
import rich
from tqdm import tqdm

from config import AFL_FUZZ, LIBFUZZER_DRIVER
from utils import check_call, run

VERSIONS = ("bic-before", "bic-after")


class Project:
    def __init__(self, name, version, tag):
        json_row = next(
            filter(lambda x: x["name"] == name, json.load(open("project_config.json"))),
            None,
        )
        if json_row is None:
            raise ValueError(f"Project {name} not found in project_config.json")

        if version not in VERSIONS:
            raise ValueError(f"Version {version} not found in project_config.json")

        if "fuzzer-libs" in json_row:
            self.fuzzer_libs = list(json_row["fuzzer-libs"])
        else:
            self.fuzzer_libs = []

        self.name = name
        self.project = name.split("-")[0]
        self.version = version
        self.tag = tag
        self.hash = json_row[version]
        self.sanitizer = json_row["sanitizer"]
        self.fuzzer = json_row["fuzzer"]
        self.true_positive = list(json_row["true-positive"])
        self.changed_functions = json_row["changed-functions"]
        self.true_positive_loc = json_row["true-positive-loc"]

        build_name = f"{name}/{version}/{tag}"

        self.artifact = Path.cwd() / "artifacts" / name / version
        self.src_dir = Path.cwd() / "build" / "src" / build_name
        self.src_project_dir = self.src_dir / self.project
        self.out_dir = Path.cwd() / "build" / "out" / build_name
        self.work_dir = Path.cwd() / "build" / "work" / build_name
        self.data_dir = Path.cwd() / "data" / name
        self.corpus = self.data_dir / "corpus"
        self.seed_dir = self.out_dir / f"{self.fuzzer}_seed_corpus"

        self.bin = self.out_dir / self.fuzzer

        self.fuzzer_libs = list(
            map(lambda x: x.replace("$SRC", str(self.src_dir)), self.fuzzer_libs)
        )
        self.fuzzer_libs = list(
            map(lambda x: x.replace("$WORK", str(self.work_dir)), self.fuzzer_libs)
        )

        self.fuzz_out_dir = (
            lambda x: self.data_dir / "system_fuzz" / f"{self.fuzzer}_out_{x}"
        )

    def get_source(self):
        image_name = f"regression-unit-framework/{self.name}:{self.version}"
        docker_build_cmd = [
            "docker",
            "build",
            "-t",
            image_name,
            f"artifacts/{self.name}/{self.version}",
        ]

        check_call(docker_build_cmd, cwd=Path.cwd())

        container_id = (
            subprocess.check_output(["docker", "create", image_name]).decode().strip()
        )
        self.src_dir.mkdir(parents=True, exist_ok=True)

        check_call(["docker", "cp", f"{container_id}:/src/.", self.src_dir])
        check_call(["docker", "rm", container_id])

    def _build(self, new_env, debug=False):
        default_env = {
            "OUT": str(self.out_dir),
            "SRC": str(self.src_dir),
            "WORK": str(self.work_dir),
            "FUZZER_LIB": " ".join(self.fuzzer_libs),
        }

        new_env.update(default_env)

        assert (self.src_dir / "build.sh").exists()

        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        build_cmd = ["bash", "../build.sh"]

        run(build_cmd, cwd=self.src_project_dir, env=new_env, quiet=(not debug))

    def build_aflpp(self, debug=False):
        new_env = {
            "LIB_FUZZING_ENGINE": str(
                Path.cwd() / "tools" / "AFLplusplus" / "libAFLDriver.a"
            ),
            "CC": str(Path.cwd() / "tools" / "AFLplusplus" / "afl-clang-fast"),
            "CXX": str(Path.cwd() / "tools" / "AFLplusplus" / "afl-clang-fast++"),
            "CFLAGS": "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "CXXFLAGS": "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        }

        if self.sanitizer == "address":
            new_env["AFL_USE_ASAN"] = "1"
        elif self.sanitizer == "none":
            pass
        elif self.sanitizer == "undefined":
            new_env["AFL_USE_UBSAN"] = "1"
        else:
            new_env["CFLAGS"] += " " + self.sanitizer
            new_env["CXXFLAGS"] += " " + self.sanitizer

        self._build(new_env, debug=debug)

        shutil.rmtree(self.seed_dir, ignore_errors=True)
        self.seed_dir.mkdir(parents=True)

        # Add empty file to seed directory
        (self.seed_dir / "input").write_text("input")

        # Unzip seed corpus if exists
        seed_corpus_zip = self.out_dir / f"{self.fuzzer}_seed_corpus.zip"

        if seed_corpus_zip.exists():
            shutil.unpack_archive(seed_corpus_zip, self.seed_dir)

    def build_aflchurn(self, debug=False):
        new_env = {
            "LIB_FUZZING_ENGINE": str(LIBFUZZER_DRIVER),
            "CC": str(Path.cwd() / "tools" / "AFLChurn" / "afl-clang-fast"),
            "CXX": str(Path.cwd() / "tools" / "AFLChurn" / "afl-clang-fast++"),
            "AFLCHURN": str(Path.cwd() / "tools" / "AFLChurn"),
            "CFLAGS": "-O0 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g",
            "CXXFLAGS": "-O0 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -g",
        }

        self._build(new_env, debug=debug)

    def build_gnu(self, save_temps=True, debug=False):
        new_env = {
            "LIB_FUZZING_ENGINE": str(LIBFUZZER_DRIVER),
            "CC": "gcc",
            "CXX": "g++",
            "CFLAGS": "-O0 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "CXXFLAGS": "-O0 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "SAVE_TEMPS": "-save-temps" if save_temps else "",
        }

        self._build(new_env, debug=debug)

    def build_gllvm(self):
        new_env = {
            "LIB_FUZZING_ENGINE": str(LIBFUZZER_DRIVER),
            "CC": "gclang",
            "CXX": "gclang++",
            "CFLAGS": "-O0 -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "CXXFLAGS": "-O0 -g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        }

        self._build(new_env)

    def build_coverage(self):
        new_env = {
            "LIB_FUZZING_ENGINE": str(LIBFUZZER_DRIVER),
            "CC": "clang",
            "CXX": "clang++",
            "CFLAGS": "-O0 -g -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "CXXFLAGS": "-O0 -g -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "COVERAGE_FLAGS": "--coverage -fPIC",
        }

        self._build(new_env)

    def get_function_list(self):
        get_bc_cmd = ["get-bc", "-o", f"{self.bin}.bc", self.bin]
        opt_cmd = [
            "opt",
            "-enable-new-pm=0",
            "-load",
            f"tools/function_list/lib/libprintfunc.so",
            "--PrintFunc",
            f"{self.bin}.bc",
            "-o",
            "/dev/null",
        ]

        check_call(get_bc_cmd)
        out = check_call(opt_cmd)
        out = out.stdout.decode().splitlines()

        def process_line(line):
            space = line.find(" ")
            filename = line[:space]
            line = line[space + 1 :]
            space = line.rfind(" ")
            end = int(line[space + 1 :])
            line = line[:space]
            space = line.rfind(" ")
            start = int(line[space + 1 :])
            line = line[:space]
            function = line
            return {
                "filename": filename,
                "function": function,
                "start": start,
                "end": end,
            }

        out = map(process_line, out)
        out = list(
            filter(lambda x: x["filename"].startswith(str(self.src_project_dir)), out)
        )
        return out

    def build_replay(self, debug=False):
        if self.sanitizer == "address":
            san_flag = "-fsanitize=address"
        elif self.sanitizer == "undefined":
            san_flag = "-fsanitize=undefined"
        else:
            san_flag = self.sanitizer

        new_env = {
            "LIB_FUZZING_ENGINE": str(LIBFUZZER_DRIVER),
            "CC": "clang",
            "CXX": "clang++",
            "CFLAGS": f"-O0 -g -fno-omit-frame-pointer {san_flag} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
            "CXXFLAGS": f"-O0 -g -fno-omit-frame-pointer {san_flag} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
        }

        self._build(new_env, debug=debug)

    def run_failing_testcase(self):
        testcase_loc = Path.cwd() / "artifacts" / self.name / "fail_testcase"
        if not testcase_loc.exists():
            rich.print(f"[red]Please put the failing testcase in {testcase_loc}.")
            project, issue = self.name.split("-")
            rich.print(
                f"[red]Maybe found in https://bugs.chromium.org/p/oss-fuzz/issues/detail?id={issue}&q={project}"
            )
            exit(1)
        run(
            [self.bin, testcase_loc],
            cwd=self.out_dir,
            env={"UBSAN_OPTIONS": "print_stacktrace=1"},
        )

    def check_corpus_correctness(self):
        corpus = list(self.corpus.iterdir())
        pool = mp.Pool(mp.cpu_count())

        def check_one(testcase):
            try:
                subprocess.check_call([self.bin, testcase], timeout=10)
            except subprocess.CalledProcessError:
                rich.print(f"[red]Error: {testcase}")
            except subprocess.TimeoutExpired:
                rich.print(f"[red]Timeout: {testcase}")

        for _ in tqdm(pool.imap_unordered(check_one, corpus), total=len(corpus)):
            pass

    def run_fuzz(self, i, timeout, debug):
        fuzz_out_dir = self.fuzz_out_dir(i)

        # Init output directory
        shutil.rmtree(fuzz_out_dir, ignore_errors=True)
        fuzz_out_dir.mkdir(parents=True)

        new_env = {"AFL_NO_UI": "1", "AFL_IGNORE_SEED_PROBLEMS": "1"}
        cmd = [
            "timeout",
            str(timeout),
            AFL_FUZZ,
            "-i",
            self.seed_dir,
            "-o",
            fuzz_out_dir,
        ]

        dict = self.out_dir / f"{self.fuzzer}.dict"

        if dict.exists():
            cmd += ["-x", str(dict)]

        cmd += ["--", self.bin, "@@"]

        run(cmd, new_env, quiet=True)

        return fuzz_out_dir / "default" / "crashes"
