import argparse
import shutil
import subprocess

import pathos.multiprocessing as mp
from tqdm import tqdm

from carve_system import SystemCarving
from config import *
from project_base import Project
from unit_fuzz import get_top_k
from unit_prioritization import UnitPrioritization
from utils import *


def get_parser():
    parser = argparse.ArgumentParser(
        "helper.py", description="regression unit fuzzing helpers"
    )
    subparsers = parser.add_subparsers(dest="command", help="command help")

    replay_parser = subparsers.add_parser("replay", help="replay")
    replay_parser.add_argument("artifact")
    replay_parser.add_argument(
        "--clear", action="store_true", help="clean old src and out directory"
    )

    unit_prioritization_parser = subparsers.add_parser(
        "unit_prioritization", help="unit prioritization"
    )
    unit_prioritization_parser.add_argument("artifact")
    unit_prioritization_parser.add_argument(
        "--clear_build",
        action="store_true",
        default=False,
        help="clear build directory",
    )
    unit_prioritization_parser.add_argument(
        "--clear_data", action="store_true", default=False, help="clear data directory"
    )
    unit_prioritization_parser.add_argument(
        "--limit", type=int, default=None, help="limit of callseq analysis"
    )
    unit_prioritization_parser.add_argument(
        "--timeout", type=int, default=30, help="timeout of callseq analysis"
    )
    unit_prioritization_parser.add_argument(
        "--debug", action="store_true", default=False, help="debug"
    )

    unit_fuzz_parser = subparsers.add_parser("unit_fuzz", help="unit select")
    unit_fuzz_parser.add_argument("artifact")
    unit_fuzz_parser.add_argument(
        "-k", type=int, default=10, help="number of functions to select"
    )
    unit_fuzz_parser.add_argument(
        "-n", type=int, default=5, help="number of fuzzing instances"
    )
    unit_fuzz_parser.add_argument(
        "--clear_base_build",
        action="store_true",
        default=False,
        help="clean old src and out directory",
    )
    unit_fuzz_parser.add_argument(
        "--clear_build", action="store_true", default=False, help="clean old harness"
    )
    unit_fuzz_parser.add_argument(
        "--skip_fuzz", action="store_true", default=False, help="skip fuzzing"
    )
    unit_fuzz_parser.add_argument(
        "--skip_carving", action="store_true", default=False, help="skip carving"
    )

    unit_fuzz_parser.add_argument("--timeout", type=int, help="timeout of fuzzer")
    unit_fuzz_parser.add_argument(
        "--debug", action="store_true", default=False, help="debug"
    )
    unit_fuzz_parser.add_argument(
        "--no_parallel", action="store_true", default=False, help="no parallel carving"
    )
    unit_fuzz_parser.add_argument(
        "--timeout_crash", type=int, default=0, help="timeout of crash analysis"
    )

    # Used to compare the performance with unit fuzzing
    system_fuzz_parser = subparsers.add_parser("system_fuzz", help="system fuzz")
    system_fuzz_parser.add_argument("artifact")
    system_fuzz_parser.add_argument(
        "-n", type=int, default=50, help="number of fuzzing instances"
    )
    system_fuzz_parser.add_argument(
        "-i", type=int, default=5, help="number of clusters to deduplicate"
    )
    system_fuzz_parser.add_argument(
        "--clear",
        action="store_true",
        default=False,
        help="clean old src and out directory",
    )
    system_fuzz_parser.add_argument(
        "--timeout", type=int, help="timeout of fuzzer", required=True
    )
    system_fuzz_parser.add_argument(
        "--skip_fuzz", action="store_true", default=False, help="skip fuzzing"
    )
    system_fuzz_parser.add_argument(
        "--debug", action="store_true", default=False, help="debug"
    )
    system_fuzz_parser.add_argument(
        "--no_parallel",
        action="store_true",
        default=False,
        help="parallel system fuzzing",
    )
    system_fuzz_parser.add_argument(
        "--timeout_crash", type=int, default=0, help="timeout of crash analysis"
    )

    system_carving_parser = subparsers.add_parser(
        "system_carving", help="system carving"
    )
    system_carving_parser.add_argument("artifact")
    system_carving_parser.add_argument(
        "--timeout", type=int, default=60, help="timeout of system carving"
    )
    system_carving_parser.add_argument(
        "--no_parallel",
        action="store_true",
        default=False,
        help="parallel system carving",
    )
    system_carving_parser.add_argument(
        "-k", type=int, default=10, help="number of functions to select"
    )
    system_carving_parser.add_argument(
        "--limit", type=int, default=20000, help="limit of callseq analysis"
    )
    system_carving_parser.add_argument(
        "--clear",
        action="store_true",
        default=False,
        help="clean old src and out directory",
    )
    system_carving_parser.add_argument(
        "--no_carving", action="store_true", default=False, help="skip carving"
    )
    system_carving_parser.add_argument(
        "--debug", action="store_true", default=False, help="debug"
    )
    system_carving_parser.add_argument(
        "--raw", action="store_true", default=False, help="raw carving"
    )

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("artifact")
    build_parser.add_argument("--version", default="bic-after")
    build_parser.add_argument(
        "--compiler", default="gllvm", choices=["gllvm", "gnu", "aflpp"]
    )
    build_parser.add_argument(
        "--tag",
        default="gllvm",
        choices=["gllvm", "gnu", "aflpp", "coverage", "replay", "tmp"],
    )
    build_parser.add_argument("--option", choices=["coverage", "sanitizer"])
    build_parser.add_argument(
        "--clear", action="store_true", help="clean old src and out directory"
    )

    corpus_correctness_parser = subparsers.add_parser(
        "corpus_correctness", help="corpus correctness"
    )
    corpus_correctness_parser.add_argument("artifact")

    coverage_parser = subparsers.add_parser("coverage", help="coverage")
    coverage_parser.add_argument("artifact")
    coverage_parser.add_argument("--dir", required=True)
    coverage_parser.add_argument(
        "--clear", action="store_true", help="clean old src and out directory"
    )

    return parser


if __name__ == "__main__":
    parser = get_parser()
    args = parser.parse_args()

    if args.command == "build":
        p = Project(args.artifact, args.version, tag=args.tag)

        if args.clear:
            subprocess.run(["rm", "-rf", p.src_dir, p.out_dir, p.work_dir], shell=True)

        p.get_source()

        if args.compiler == "gllvm":
            p.build_gllvm()
        elif args.compiler == "gnu":
            p.build_gnu()
        elif args.compiler == "replay":
            p.build_replay()
        elif args.compiler == "aflpp":
            p.build_aflpp()
        else:
            assert False, "Unknown compiler"

    if args.command == "replay":
        # Requires gllvm base with sanitizer
        version = "bic-after"
        p = Project(args.artifact, version, tag="replay")

        # Check if src exists and last modified time of artifacts is older than src
        if (
            not (
                p.src_dir.exists()
                and (
                    get_last_modified_date(p.src_dir)
                    > get_last_modified_date(p.artifact)
                )
            )
        ) or args.clear:
            # Remove old src directory
            subprocess.run(["rm", "-rf", p.src_dir, p.out_dir, p.work_dir], shell=True)

            p.get_source()
            p.build_replay()

        p.run_failing_testcase()

    elif args.command == "unit_prioritization":
        version = "bic-after"
        p = Project(args.artifact, version, tag="gllvm")

        # Check if src exists and last modified time of artifacts is older than src
        if (
            not (
                p.src_dir.exists()
                and (
                    get_last_modified_date(p.src_dir)
                    > get_last_modified_date(p.artifact)
                )
            )
        ) or args.clear_build:
            # Remove old src directory
            subprocess.run(["rm", "-rf", p.src_dir, p.out_dir, p.work_dir], shell=True)

            p.get_source()
            p.build_gllvm()

        p = UnitPrioritization(args.artifact, version, tag="gllvm")

        # Check if last modified time of binary is older than callgraph dot file
        if (
            not (
                p.dot_file.exists()
                and (p.dot_file.stat().st_mtime > p.bin.stat().st_mtime)
            )
        ) or args.clear_build:
            p.build_callgraph()

        p.static_analysis()

        # Check if last modified time of binary is older than funcseq instrumented binary
        if (
            not (
                p.funcseq.exists()
                and (p.funcseq.stat().st_mtime > p.bin.stat().st_mtime)
            )
        ) or args.clear_build:
            p.build_callseq()

        if args.clear_data:
            subprocess.run(["rm", "-rf", p.funcseq_out])

        p.callseq_analysis(
            limit=args.limit, timeout=args.timeout, debug=args.debug, skip_exist=True
        )

        p.ensanble()

    elif args.command == "unit_fuzz":
        p = Project(args.artifact, "bic-after", tag="gnu")
        if args.clear_base_build:
            shutil.rmtree(p.src_dir, ignore_errors=True)
            shutil.rmtree(p.work_dir, ignore_errors=True)

        if not (
            p.src_dir.exists()
            and (get_last_modified_date(p.src_dir) > get_last_modified_date(p.artifact))
        ):
            p.get_source()
            p.build_gnu(debug=args.debug)

        units = get_top_k(args.artifact, "bic-after", k=args.k, decl_save=True)
        repeat = range(args.n)

        for u in units:
            u.generate_harness(ignore_exist=(not args.clear_build), debug=args.debug)
            if not (
                u.fuzzer_bin.exists()
                and u.fuzzer_bin.stat().st_mtime > u.harness_src.stat().st_mtime
            ):
                u.build_fuzzer(debug=args.debug)
                u.build_trace()
                u.build_carving()

        # Product of all possible combinations
        jobs = [(u, r) for u in units for r in repeat]

        if not args.skip_fuzz:
            if args.no_parallel:
                for u, i in tqdm(jobs):
                    u.run_fuzzer(i, timeout=args.timeout)
            else:
                with mp.Pool(mp.cpu_count()) as pool:
                    for _ in pool.imap_unordered(
                        lambda x: x[0].run_fuzzer(x[1], timeout=args.timeout), jobs
                    ):
                        pass

        if not args.skip_carving:
            for u, i in jobs:
                kill_ipcs()
                u.run_carving(i, multi=(not args.no_parallel), timeout=10)

        crashes = [
            (i, u, testcase)
            for u, i in jobs
            for testcase in (u.fuzz_out_dir(i) / "default" / "crashes").glob("id:*")
        ]

        def time_filter(path):
            name = path.name
            time_start = name.find("time:") + 5
            time_end = name.find(",", time_start)
            return int(name[time_start:time_end]) <= args.timeout_crash

        if args.timeout_crash > 0:
            crashes = list(filter(lambda x: time_filter(x[2]), crashes))

        def postprocess_crash(i, u, testcase):
            stacktrace = get_stacktrace(u.trace_bin, testcase, debug=args.debug)
            if stacktrace is None:
                return None

            out = parse_stacktrace(stacktrace, u.src_dir)
            if args.debug:
                print(out)

            conn = create_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE unit_carving SET sanitizer_report=%s WHERE project=%s AND function_name=%s AND testcase=%s AND expr_index=%s",
                (stacktrace, args.artifact, u.function, testcase.name, i),
            )

            conn.commit()
            cursor.close()
            conn.close()

            return "\n".join(out)

        collect = [set() for _ in repeat]
        if args.no_parallel:
            for i, u, testcase in tqdm(crashes):
                trace = postprocess_crash(i, u, testcase)
                if trace is not None:
                    collect[i].add(trace)
        else:
            with mp.Pool(mp.cpu_count()) as pool:
                for i, trace in tqdm(
                    pool.imap_unordered(
                        lambda x: (x[0], postprocess_crash(*x)), crashes
                    ),
                    total=len(crashes),
                ):
                    if trace is not None:
                        collect[i].add(trace)

        for i in repeat:
            print(f"Iter {i}: {len(collect[i])} unique crashes")
            if args.debug:
                for trace in collect[i]:
                    print(list(trace.split("\n")))

        true_loc = p.true_positive_loc
        true_loc = true_loc.split("/")[-1]
        true_loc = ":".join(true_loc.split(":")[:2])

        print(true_loc)

        out_text = (
            ",".join([str(len(collect[i])) for i in repeat])
            + "\n"
            + ",".join(
                [
                    str(len(list(filter(lambda x: true_loc in x, collect[i]))))
                    for i in repeat
                ]
            )
        )

        out_file = p.data_dir / "unit_fuzz" / f"summary.txt"
        out_file.write_text(out_text)

        print(out_text)

    elif args.command == "system_fuzz":
        fp = Project(args.artifact, "bic-after", tag="aflpp")
        rp = Project(args.artifact, "bic-after", tag="replay")

        if args.clear:
            shutil.rmtree(fp.src_dir, ignore_errors=True)
            shutil.rmtree(fp.out_dir, ignore_errors=True)
            shutil.rmtree(fp.work_dir, ignore_errors=True)
            shutil.rmtree(rp.src_dir, ignore_errors=True)
            shutil.rmtree(rp.out_dir, ignore_errors=True)
            shutil.rmtree(rp.work_dir, ignore_errors=True)

        if not (
            fp.src_dir.exists()
            and (
                get_last_modified_date(fp.src_dir) > get_last_modified_date(fp.artifact)
            )
        ):
            fp.get_source()
            fp.build_aflpp(debug=args.debug)

        if not (
            rp.src_dir.exists()
            and (
                get_last_modified_date(rp.src_dir) > get_last_modified_date(rp.artifact)
            )
        ):
            rp.get_source()
            rp.build_replay(debug=args.debug)

        if not args.skip_fuzz:
            shutil.rmtree(fp.data_dir / "system_fuzz", ignore_errors=True)
            with mp.Pool(mp.cpu_count()) as pool:
                # fp.run_fuzz(i, timeout=args.timeout), range(args.n)
                for _ in pool.imap_unordered(
                    lambda i: fp.run_fuzz(i, timeout=args.timeout, debug=args.debug),
                    range(args.n),
                ):
                    pass

        crashes = [
            (i, testcase)
            for i in range(args.n)
            for testcase in (fp.fuzz_out_dir(i) / "default" / "crashes").glob("id:*")
        ]

        def time_filter(path):
            name = path.name
            time_start = name.find("time:") + 5
            time_end = name.find(",", time_start)
            return int(name[time_start:time_end]) <= args.timeout_crash

        if args.timeout_crash > 0:
            crashes = list(filter(lambda x: time_filter(x[1]), crashes))

        def postprocess_crash(i, testcase):
            stacktrace = get_stacktrace(rp.bin, testcase, debug=args.debug)
            if stacktrace is None:
                return None
            out = parse_stacktrace(stacktrace, rp.src_dir)
            if args.debug:
                print(out)

            return "\n".join(out)

        collect = [set() for _ in range(args.i)]
        cluster_size = args.n // args.i

        if args.no_parallel:
            for i, testcase in tqdm(crashes):
                trace = postprocess_crash(i, testcase)
                if trace is not None:
                    collect[i // cluster_size].add(trace)
        else:
            with mp.Pool(mp.cpu_count()) as pool:
                for i, trace in tqdm(
                    pool.imap_unordered(
                        lambda x: (x[0], postprocess_crash(*x)), crashes
                    ),
                    total=len(crashes),
                ):
                    if trace is not None:
                        collect[i // cluster_size].add(trace)

        for i in range(args.i):
            print(f"Cluster {i}: {len(collect[i])} unique crashes")
            if args.debug:
                for trace in collect[i]:
                    print(list(trace.split("\n")))

        true_loc = fp.true_positive_loc
        true_loc = true_loc.split("/")[-1]
        true_loc = ":".join(true_loc.split(":")[:2])

        print(true_loc)

        out_text = (
            ",".join([str(len(collect[i])) for i in range(args.i)])
            + "\n"
            + ",".join(
                [
                    str(len(list(filter(lambda x: true_loc in x, collect[i]))))
                    for i in range(args.i)
                ]
            )
        )

        out_file = fp.data_dir / "system_fuzz" / f"summary.txt"
        out_file.write_text(out_text)

        print(out_text)

    elif args.command == "system_carving":
        gnu_project = Project(args.artifact, "bic-after", tag="gnu")
        p = SystemCarving(args.artifact, "bic-after", tag="gllvm")
        if args.clear:
            shutil.rmtree(gnu_project.src_dir, ignore_errors=True)
            shutil.rmtree(gnu_project.work_dir, ignore_errors=True)
            shutil.rmtree(p.src_dir, ignore_errors=True)
            shutil.rmtree(p.work_dir, ignore_errors=True)

        if not (
            gnu_project.src_dir.exists()
            and (
                get_last_modified_date(gnu_project.src_dir)
                > get_last_modified_date(gnu_project.artifact)
            )
        ):
            gnu_project.get_source()
            gnu_project.build_gnu(debug=args.debug)

        funcs = get_top_k(args.artifact, "bic-after", k=args.k, decl_save=True)

        if not (
            p.src_dir.exists()
            and (get_last_modified_date(p.src_dir) > get_last_modified_date(p.artifact))
        ):
            p.get_source()
            p.build_gllvm()

        if (
            not (p.bin.exists() and (p.bin.stat().st_mtime > p.src_dir.stat().st_mtime))
        ) or args.clear:
            p.build(debug=args.debug)

        if not args.no_carving:
            kill_ipcs()
            p.run(
                limit=args.limit,
                timeout=args.timeout,
                parallel=(not args.no_parallel),
                debug=args.debug,
                raw=args.raw,
            )

        p.count_system_testcases(funcs)

    elif args.command == "coverage":
        p = Project(args.artifact, "bic-after", tag="coverage")
        if args.clear:
            shutil.rmtree(p.src_dir, ignore_errors=True)
            shutil.rmtree(p.out_dir, ignore_errors=True)
            shutil.rmtree(p.work_dir, ignore_errors=True)

        if not p.src_dir.exists():
            p.get_source()
            p.build_coverage()

        corpus_dir = Path(args.dir)
        # Check if relative
        if not corpus_dir.is_absolute():
            corpus_dir = Path.cwd() / corpus_dir

        for testcase in tqdm(list(corpus_dir.glob("id:*"))):
            check_call([p.bin, testcase], cwd=p.src_dir, print=True)

    else:
        # help message
        parser.print_help()
