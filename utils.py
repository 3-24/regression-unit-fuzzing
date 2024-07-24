import os
import re
import subprocess
from io import StringIO
from pathlib import Path

import pandas as pd
import rich
from tree_sitter import Language, Parser


def get_cmd(cmd, env={}):
    env_str = " ".join([f'{key}="{value}"' for key, value in env.items()])
    cmd_str = " ".join(map(str, cmd))
    return f"{env_str} {cmd_str}"


def run(cmd, env={}, cwd=None, print=True, quiet=False, timeout=None):
    if print:
        if cwd is None:
            rich.print(f"[green]{get_cmd(cmd, env)}")
        else:
            rich.print(f"[green]cd {cwd} && \\ \n{get_cmd(cmd, env)}")

    _env = os.environ.copy()
    _env.update(env)

    if quiet:
        subprocess.run(
            cmd,
            env=_env,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    else:
        subprocess.run(cmd, env=_env, cwd=cwd, timeout=timeout)


def check_call(cmd, env={}, cwd=None, print=True, timeout=None, quiet=False):
    if print:
        if cwd is None:
            rich.print(f"[green]{get_cmd(cmd, env)}")
        else:
            rich.print(f"[green]cd {cwd} && \\ \n{get_cmd(cmd, env)}")

    _env = os.environ.copy()
    _env.update(env)

    stdout_pipe = subprocess.DEVNULL if quiet else subprocess.PIPE
    stderr_pipe = subprocess.DEVNULL if quiet else subprocess.PIPE

    out = subprocess.run(
        cmd, env=_env, cwd=cwd, timeout=timeout, stdout=stdout_pipe, stderr=stderr_pipe
    )
    if out.returncode != 0:
        if quiet:
            raise subprocess.CalledProcessError(out.returncode, cmd)
        else:
            raise subprocess.CalledProcessError(
                out.returncode, cmd, out.stdout, out.stderr
            )
    return out


def kill_ipcs():
    cmd = ["bash", "assets/kill_ipcs.sh"]
    subprocess.run(cmd)


def kill_old_ipcs(timeout):
    out = check_call(["ipcs", "-m", "-t"], print=False)
    out = out.stdout.decode("utf-8")
    out = out[out.find("shmid") :]

    # Parse output as pandas dataframe
    df = pd.read_fwf(StringIO(out))

    # Filter by owner "youngseok"
    df = df[df["owner"] == "youngseok"]

    # "Not set" is a string, convert to None
    df = df.replace("Not set", None)

    # attached, detached, changed as timestamp
    # format is Mar  6 22:54:03
    df["attached"] = pd.to_datetime(df["attached"], format="%b %d %H:%M:%S")
    df["detached"] = pd.to_datetime(df["detached"], format="%b %d %H:%M:%S")
    df["changed"] = pd.to_datetime(df["changed"], format="%b %d %H:%M:%S")

    # Set year to current year
    df["attached"] = df["attached"].apply(
        lambda x: x.replace(year=pd.Timestamp.now().year)
    )
    df["detached"] = df["detached"].apply(
        lambda x: x.replace(year=pd.Timestamp.now().year)
    )
    df["changed"] = df["changed"].apply(
        lambda x: x.replace(year=pd.Timestamp.now().year)
    )

    # Get current time
    now = pd.Timestamp.now()

    # Filter by time
    df = df[(now - df["detached"]).dt.total_seconds() > timeout]

    # Kill ipcs
    for shmid in df["shmid"]:
        print(shmid)
        check_call(["ipcrm", "-m", str(shmid)], print=False)


# Recursively get last time modified in directory
def get_last_modified_date(path_dir):
    last_modified = 0
    for root, _, files in os.walk(path_dir):
        for file in files:
            last_modified = max(
                last_modified, os.path.getmtime(os.path.join(root, file))
            )
    return last_modified


def get_declaration(src_file, function):
    parser = Parser()
    parser.set_language(Language("tools/c_language.so", "c"))

    content = src_file.read_text()
    tree = parser.parse(bytes(content, "utf8"))

    def handle_function_definition(node):
        # Find function declarator
        function_declarator = None

        out = []

        for child in node.children:
            if child.type == "function_declarator":
                function_declarator = child
                out.append(child.text)
                break
            elif child.type == "pointer_declarator":
                pointer_out = []
                t = child
                while t.type != "function_declarator":
                    pointer_out.append(t.children[0].text)
                    t = t.children[1]

                assert t.type == "function_declarator"
                function_declarator = t
                pointer_out.append(function_declarator.text)
                out.append(b"".join(pointer_out))
                break
            else:
                out.append(child.text)

        if function_declarator is None:
            return None

        # Find function name
        function_name = None
        for child in function_declarator.children:
            if child.type == "identifier":
                function_name = child

        if function_name is not None and function_name.text == function.encode("utf8"):
            out = b" ".join(out)
            # Reduce whitespace and linebreak to single space
            out = re.sub(b"[\n\r\t ]+", b" ", out)

            return out.decode("utf-8")

    # Iterate over function declarations
    for node in tree.root_node.children:
        if node.type == "preproc_ifdef":
            for child in node.children:
                if child.type == "function_definition":
                    try:
                        result = handle_function_definition(child)
                    except IndexError:
                        continue
                    if result is not None:
                        return result

        elif node.type == "function_definition":
            try:
                result = handle_function_definition(node)
            except IndexError:
                continue
            if result is not None:
                return result

    raise ValueError(f"Function {function} not found in {src_file}")


def find_preprocessed_file(project_conf, function):
    rich.print(
        f"[green]{project_conf.src_project_dir.relative_to(Path.cwd())}: Searching for {function}"
    )

    parser = Parser()
    parser.set_language(Language("tools/c_language.so", "c"))

    # Find all files with .i extension that contain the target function
    cmd = [
        "find",
        ".",
        "-type",
        "f",
        "-name",
        "*.i",
        "-exec",
        "grep",
        "-q",
        function,
        "{}",
        ";",
        "-print",
    ]

    output_candidates = (
        subprocess.check_output(cmd, cwd=project_conf.src_project_dir)
        .decode("utf-8")
        .splitlines()
    )

    for preprocessed_file in output_candidates:
        full_path = project_conf.src_project_dir / preprocessed_file
        content = bytes(full_path.read_text(), "utf8")

        # Filter lines starting with #
        content = b"\n".join(
            filter(lambda line: not line.startswith(b"#"), content.split(b"\n"))
        )

        tree = parser.parse(content)
        for node in tree.root_node.children:
            if node.type == "function_definition":
                # Check if function body exists
                body_exists = False
                for child in node.children:
                    if child.type == "compound_statement":
                        body_exists = True
                        break

                if not body_exists:
                    continue

                # Check if name occurs

                function_declarator = None

                # Find function declarator
                for child in node.children:
                    if child.type == "function_declarator":
                        function_declarator = child
                        break
                    elif child.type == "pointer_declarator":
                        t = child
                        while t.type == "pointer_declarator":
                            t = t.children[1]

                        if t.type != "function_declarator":
                            continue

                        assert t.type == "function_declarator"
                        function_declarator = t
                        break

                if function_declarator is None:
                    continue

                assert function_declarator is not None

                # Check if function name matches
                name_match = False
                for child in function_declarator.children:
                    if child.type == "identifier" and child.text == function.encode(
                        "utf8"
                    ):
                        name_match = True
                        break

                if not name_match:
                    continue

                if body_exists:
                    rich.print(
                        f"[green]{project_conf.src_project_dir.relative_to(Path.cwd())}: Found {function} in {preprocessed_file}"
                    )
                    return Path(preprocessed_file)

    rich.print(
        f"[red]{project_conf.src_project_dir.relative_to(Path.cwd())}: {function} not found"
    )
    return None


def get_stacktrace(binary, testcase, timeout=None, debug=False):
    env = {"ASAN_OPTIONS": "detect_leaks=0", "UBSAN_OPTIONS": "print_stacktrace=1"}

    # cmd = [binary, testcase]
    cmd = ["gdb", "-ex", "r", "-ex", "bt", "-batch", "--args", binary, testcase]

    if debug:
        rich.print(f"[green]{get_cmd(cmd, env)}")

    output = subprocess.run(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        cwd=binary.parent,
    )

    stdout = output.stdout.decode("utf-8")
    stderr = output.stderr.decode("utf-8")

    if debug:
        print(stdout)
        print("=" * 80)
        print(stderr)

    if re.search("==\d+==ERROR: AddressSanitizer:", stderr) is not None:
        return stderr
    elif re.search("Program received signal SIG(SEGV|ABRT|FPE)", stdout) is not None:
        return stdout
    elif re.search("UndefinedBehaviorSanitizer:", stderr) is not None:
        return stderr
    elif "exited normally" in stdout and not "SUMMARY" in stderr:
        return None
    else:
        assert False


def parse_stacktrace(text, src_dir, top=3, include_function_name=False):

    def _parse_sanitizer_trace(text, src_dir, top=3):
        lines = map(str.lstrip, text.split("\n"))
        traces = []
        for line in lines:
            # #0 0x597393 in curl_mvsnprintf /home/youngseok/regression-unit-framework/build/src/curl-8000/bic-after/replay/curl/lib/mprintf.c:1013:22
            if line[0] != "#":
                continue
            hex_start = line.find("0x")
            assert hex_start != -1
            hex_end = line.find(" ", hex_start)
            addr = line[hex_start:hex_end]
            line = line[hex_end + 1 :]

            # in exists
            if "in" == line[:2]:
                line = line[3:]
                next_open_bracket = line.find("(")
                next_empty = line.find(" ")
                if next_open_bracket != -1 and next_open_bracket < next_empty:
                    func_name = line[:next_open_bracket]
                    func_end = line.find(")")
                    line = line[func_end + 1 :]
                else:
                    func_end = next_empty
                    func_name = line[:func_end]
                    line = line[func_end + 1 :]
            else:
                continue

            source_loc = line
            if source_loc.find(":") == -1:
                # libxml2-17737/bic-after/replay/libxml2_xml_reader_for_file_fuzzer+0x499ff3
                continue
            filename, row, col = source_loc.split(":")

            try:
                filename = Path(filename).relative_to(src_dir)
            except ValueError:
                filename = Path(filename)

            if include_function_name:
                traces.append((func_name, f"{filename}:{row}:{col}"))
            else:
                traces.append(f"{filename}:{row}:{col}")
            if len(traces) >= top:
                break

        return traces

    # ==22281==ERROR: AddressSanitizer: heap-buffer-overflow on ...

    if (rasan_match := re.search("==\d+==ERROR: AddressSanitizer: ", text)) is not None:
        matched_line_start = rasan_match.start()
        start = text.find("\n", matched_line_start) + 1
        end = text.find("\n\n", start)
        text = text[start:end]
        return _parse_sanitizer_trace(text, src_dir, top)
    elif "UndefinedBehaviorSanitizer:" in text:
        # Find line with format "    #0 0x63f1f1 in ndpi/src/lib/protocols/avast_securedns.c:40:13"
        start = re.search(r"    #\d+", text).start()
        end = text.find("\n\n", start)
        text = text[start:end]
        return _parse_sanitizer_trace(text, src_dir, top)
    # SIGSEGV or SIGABRT
    elif (
        gdb_match := re.search("Program received signal SIG(SEGV|ABRT|FPE)", text)
    ) is not None:
        text = text[gdb_match.start() :]
        lines = map(str.lstrip, text.split("\n"))
        lines = list(filter(lambda x: x.startswith("#"), lines))
        _lines = []
        for i in range(len(lines)):
            if not "at" in lines[i]:
                _lines = []
            else:
                _lines.append(lines[i])
        lines = _lines
        if include_function_name:
            locs = []
            for line in lines:
                toks = line.split()
                locs.append((toks[3], toks[-1]))
        else:
            locs = list(map(lambda x: x.split()[-1], lines))
        return locs[:top]
    else:
        print(text)
        assert False
