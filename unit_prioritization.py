import random
import subprocess
import sys
from collections import Counter
from queue import Queue

import pandas as pd
import pathos.multiprocessing as mp
import pydot
import rich
from tqdm.rich import tqdm

from config import PRINT_FUNCTION, corpus_dir
from project_base import Project
from utils import check_call, get_cmd


class UnitPrioritization(Project):
    def __init__(self, name, version, tag=None):
        super().__init__(name, version, tag)
        self.funcseq = self.bin.with_suffix(".funcseq")
        self.dot_file = self.out_dir / f"{self.bin}.bc.callgraph.dot"
        self.funcseq_out = self.out_dir / "funcseq"

        self.data_dir.mkdir(parents=True, exist_ok=True)

    def build_callseq(self):
        assert self.bin.exists()
        get_bc_cmd = ["get-bc", "-o", f"{self.bin}.bc", self.bin]
        opt_cmd = [
            "opt",
            "-enable-new-pm=0",
            "-load",
            f"{PRINT_FUNCTION}/libprintfunc.so",
            "--PrintFunc",
            f"{self.bin}.bc",
            "-o",
            f"{self.funcseq}.bc",
        ]
        compile_cmd = [
            "clang++",
            f"{self.funcseq}.bc",
            "-L",
            PRINT_FUNCTION,
            "-lpf-rt",
            "-o",
            self.funcseq,
        ] + self.fuzzer_libs

        check_call(get_bc_cmd)
        check_call(opt_cmd)
        check_call(compile_cmd)

    def build_callgraph(self):
        get_bc_cmd = ["get-bc", "-o", f"{self.bin}.bc", self.bin]
        opt_cmd = [
            "opt",
            "-enable-new-pm=0",
            "-analyze",
            "-dot-callgraph",
            f"{self.bin}.bc",
        ]
        check_call(get_bc_cmd)
        check_call(opt_cmd)

    def callseq_analysis(self, limit=None, timeout=None, debug=False, skip_exist=True):
        # shutil.rmtree(out_dir, ignore_errors=True)
        self.funcseq_out.mkdir(parents=True, exist_ok=True)

        def run(testcase):
            assert self.funcseq.exists()

            # Run the testcase
            seq_file = self.funcseq_out / (testcase.name + ".seq")
            symbol_file = self.funcseq_out / (testcase.name + ".symbol")
            env = {"OUT_FILE": seq_file, "RECORD_FILE": symbol_file}

            try:
                if not (skip_exist and seq_file.exists() and symbol_file.exists()):
                    check_call(
                        [self.funcseq, testcase], env=env, timeout=timeout, print=False
                    )
                assert seq_file.exists()
                assert symbol_file.exists()
            except subprocess.TimeoutExpired:
                rich.print(
                    f"[green]{get_cmd([self.funcseq, testcase], env=env)}[/green]"
                )
                rich.print(f"[red]Timeout: {testcase}")
                seq_file.unlink()
                symbol_file.unlink()
                return set()
            except subprocess.CalledProcessError:
                rich.print(
                    f"[green]{get_cmd([self.funcseq, testcase], env=env)}[/green]"
                )
                rich.print(f"[red]Returned non-zero: {testcase}")
                # seq_file.unlink()
                # symbol_file.unlink()
                # return set()

            # Parse the symbol file
            symbols = set()
            lines = map(lambda s: s.rstrip(), symbol_file.read_text().split("\n"))

            # Grammar: {{ index }} {{ function }} at {{ src_filename }}
            for line in lines:
                if line == "":
                    continue
                i = line.rfind(" ")
                src_filename = line[i + 1 :]
                line = line[:i]

                # Check 'at' keyword
                if "at" != line[-2:]:
                    rich.print(f"[red]Invalid file format in {symbol_file}")
                    symbol_file.unlink()
                    return set()
                line = line[:-3]

                # Parse index
                i = line.find(" ")
                try:
                    _index = int(line[:i])
                    line = line[i + 1 :]
                except ValueError:
                    rich.print(f"[red]Invalid file format in {symbol_file}")
                    symbol_file.unlink()
                    return set()

                # Parse function
                function = line

                assert function.strip() == function
                assert src_filename.strip() == src_filename

                symbols.add((src_filename, function))

            return symbols

        # Sample corpus
        corpus = list(corpus_dir(self.name).iterdir())
        if limit and len(corpus) > limit:
            corpus = random.sample(corpus, limit)

        # Run all
        if not debug:
            with mp.Pool(mp.cpu_count()) as pool:
                symbols_it = list(
                    tqdm(pool.imap_unordered(run, corpus), total=len(corpus))
                )
        else:
            symbols_it = list(tqdm(map(run, corpus), total=len(corpus)))

        # Get filename from target_function by union
        symbols_merged = set()
        for symbols in symbols_it:
            symbols_merged |= symbols

        # Tuples of changed functions
        changed_tuples = list()
        for tuple in symbols_merged:
            if tuple[1] in self.changed_functions:
                changed_tuples.append(tuple)

        print(changed_tuples)

        # Count # of cases that (f, g) co-occurs where f is changed function
        cooccurrence_counter = {tuple: Counter() for tuple in changed_tuples}

        occurrence_counter = Counter()

        for changed_tuple in changed_tuples:
            for symbols in symbols_it:
                if not changed_tuple in symbols:
                    continue
                for other_tuple in symbols:
                    cooccurrence_counter[changed_tuple][other_tuple] += 1

        for symbols in symbols_it:
            for tuple in symbols:
                occurrence_counter[tuple] += 1

        # Compute function relevance
        df = []
        for tuple in symbols_merged:
            max_relevance = 0
            co_count = 0
            count_changed = 0
            count_self = 0

            for changed_tuple in changed_tuples:
                new_relevance = (
                    cooccurrence_counter[changed_tuple][tuple]
                    * cooccurrence_counter[changed_tuple][tuple]
                    / (occurrence_counter[changed_tuple] * occurrence_counter[tuple])
                )
                if new_relevance > max_relevance:
                    max_relevance = new_relevance
                    co_count = cooccurrence_counter[changed_tuple][tuple]
                    count_changed = occurrence_counter[changed_tuple]
                    count_self = occurrence_counter[tuple]

            df.append(
                {
                    "function": tuple[1],
                    "relevance": max_relevance,
                    "cooccurrence_count": co_count,
                    "count_changed": count_changed,
                    "count_self": count_self,
                }
            )

        df = pd.DataFrame(df)
        df.to_csv(f"data/{self.name}/function_relevance_ranking.csv", index=False)
        return df

    def static_analysis(self):
        assert self.dot_file.exists()
        dot_graph = pydot.graph_from_dot_file(self.dot_file)[0]

        nodes = list(
            map(
                lambda node: (
                    "None" if node.get_label() is None else node.get_label()[2:-2]
                ),
                dot_graph.get_nodes(),
            )
        )
        inv_nodes = {}
        for i, node in enumerate(nodes):
            inv_nodes[node] = i

        graph = [[] for _ in range(len(nodes))]
        inv_graph = [[] for _ in range(len(nodes))]

        for edge in dot_graph.get_edges():
            src = dot_graph.get_node(edge.get_source())[0].get_label()[2:-2]
            dst = dot_graph.get_node(edge.get_destination())[0].get_label()[2:-2]
            graph[inv_nodes[src]].append(inv_nodes[dst])
            inv_graph[inv_nodes[dst]].append(inv_nodes[src])

        # Find changed indices
        changed_labels = set()
        for i, func in enumerate(nodes):
            if func in self.changed_functions:
                changed_labels.add(i)

        # BFS to find shortest distance
        dist = [float("inf") for _ in range(len(nodes))]
        q = Queue()

        # Initialize distance
        for label in changed_labels:
            q.put(label)
            dist[label] = 0

        visited = [False] * len(nodes)

        while not q.empty():
            label = q.get()
            if visited[label]:
                continue

            visited[label] = True

            for next_label in graph[label] + inv_graph[label]:
                if not visited[next_label]:
                    q.put(next_label)
                    dist[next_label] = min(dist[next_label], dist[label] + 1)

        out = []

        for i, d in enumerate(dist):
            func = nodes[i]
            out.append(
                {
                    "function": func,
                    "distance": d,
                    "fan-in": len(inv_graph[i]),
                    "fan-out": len(graph[i]),
                }
            )

        df = pd.DataFrame(out)
        df.to_csv(f"data/{self.name}/static_info.csv", index=False)

    def ensanble(self):
        # Load function list
        out = self.get_function_list()
        out = list(map(lambda x: {"file": x[0], "function": x[1]}, out))
        out = pd.DataFrame(out)

        relevance_fn = f"data/{self.name}/function_relevance_ranking.csv"
        static_fn = f"data/{self.name}/static_info.csv"

        dynamic_df = pd.read_csv(relevance_fn)
        static_df = pd.read_csv(static_fn)

        # Merge with default value
        out = out.merge(dynamic_df, on="function", how="left").fillna(
            0
        )  # Fill NaN with 0
        out = out.merge(static_df, on="function", how="left")
        total_rows = len(out)
        out["fan_in_out"] = out["fan-in"] + out["fan-out"]
        out["score"] = out["relevance"] + (1 / (out["distance"] + 1))
        out.sort_values(by=["score"], inplace=True, ascending=False, ignore_index=True)
        out.to_csv(f"data/{self.name}/unit_ranking.csv", index=False)

        ranking = sys.maxsize

        # Get rank of true positive
        for true_positive in self.true_positive:
            if not true_positive in out["function"].values:
                rich.print(
                    f"[red]True positive {true_positive} not found in the ranking"
                )
                continue
            new_ranking = out[out["function"] == true_positive].index[0] + 1
            ranking = min(ranking, new_ranking)

        print(f"Rank: {ranking} / {total_rows}")

        return (total_rows, ranking)
