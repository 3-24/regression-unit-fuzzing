import re
from queue import Queue

import rich

TYPE_PREFIX = ["struct", "%struct", "class", "union"]


class Value:
    def __init__(self, value, typ, reached):
        self.value = value
        self.type = typ
        self.reached = reached


def remove_type_prefix(type_name):
    type_dot_loc = type_name.find(".")
    if type_dot_loc != -1:
        type_prefix = type_name[:type_dot_loc]
        if not type_prefix in TYPE_PREFIX:
            raise Exception("Unknown type prefix: " + type_prefix)
        type_name = type_name[type_dot_loc + 1 :]

    return type_name


class PrimitiveValue(Value):
    def __init__(self, value, typ, reached):
        super().__init__(value, typ, reached)

    def dependent_ptrs(self):
        return []

    def val_string(self):
        return f"{self.value}"

    def expr_string(self):
        return f"{self.type} {self.value}"


class PointerValue(Value):
    def __init__(self, type, alloc_size, name, reached):
        super().__init__([], type, reached)
        self.alloc_size = alloc_size
        self.name = name
        self.done = False

    # WARNING: This is naive implementation.
    #      We should consider the case where two pointers are pointing each other:
    #      p1 -> p2, p3
    #      p2 -> p1,
    #      p3 -> (some used data)
    #      In this case, p1 and p2 should be marked as reached.
    #      However, this implementation will mark only p1 as reached.
    def reach_update(self):
        if self.done:
            return
        self.done = True
        for elem in self.value:
            if isinstance(elem, PointerValue):
                if not elem.done:
                    elem.reach_update()
                self.reached = self.reached or elem.reached
            else:
                self.reached = self.reached or elem.reached

    def append(self, value):
        self.value.append(value)

    def dependent_ptrs(self):
        res = []
        for elem in self.value:
            if isinstance(elem, PointerValue):
                res.append(elem)
            else:
                res.extend(elem.dependent_ptrs())
        return res

    def val_string(self):
        return f"p{self.name}"

    def expr_string(self):
        value_strs = []
        for i, elem in enumerate(self.value):
            if elem.reached:
                value_strs.append(f"{i}:{elem.val_string()}")

        # Length 2 truncation
        if len(value_strs) > 2:
            value_strs = [value_strs[0], value_strs[-1]]

        value_str = ", ".join(value_strs)
        type_str = remove_type_prefix(self.type)

        if value_strs == []:
            return f"{type_str} p{self.name}[{len(self.value)}]"
        else:
            return f"{type_str} p{self.name}[{len(self.value)}] = [{value_str}]"


class StructValue(Value):
    def __init__(self, type, reached):
        super().__init__([], type, reached)

    def append(self, value):
        self.value.append(value)

    def dependent_ptrs(self):
        res = []
        for elem in self.value:
            if isinstance(elem, PointerValue):
                res.append(elem)
            else:
                res.extend(elem.dependent_ptrs())
        return res

    def val_string(self):
        value_strs = []
        for i, val in enumerate(self.value):
            if val.reached:
                value_strs.append(f"{i}:{val.val_string()}")
        inner = "{" + ", ".join(value_strs) + "}"
        return inner

    def expr_string(self):
        # We don't know struct fields, so indicate it by indices
        value_strs = []
        for i, val in enumerate(self.value):
            if val.reached:
                if isinstance(val, PointerValue):
                    value_strs.append(f"{i}:{val.val_string()}")
                else:
                    value_strs.append(f"{i}:{val.expr_string()}")

        inner = "{" + ", ".join(value_strs) + "}"

        return f"{self.type} {inner}"


class PointerOffsetValue(Value):
    def __init__(self, base_ptr, offset, reached):
        super().__init__(None, base_ptr.type, reached)
        self.base_ptr = base_ptr
        self.offset = offset

    def dependent_ptrs(self):
        return [self.base_ptr]

    def val_string(self):
        return f"p{self.base_ptr.name}+{self.offset}"

    def expr_string(self):
        return self.val_string()


def process_context(content):
    """Main logic of postprocessing

    Args:
        content (string): Raw context string
    """
    content = map(lambda x: x.strip(), content.split("\n"))
    content = filter(lambda x: x != "", content)
    parsed_args = []

    unfinished_stack = []  # Save unfinished StructValue or PointerValue line by line
    ptr_to_index = {}  # Pointer length counter for PointerValue objects
    ptr_name2obj = {}  # PointerValue objects indexed by name

    for i, expr in enumerate(content):
        reached = expr[0]
        expr = expr[2:].strip()
        reached = reached == "%"
        # Array type
        if expr.endswith("]"):
            space_pos = expr.find(" ")
            bracket_open_pos = expr.find("[")
            bracket_close_pos = expr.find("]")
            array_type = expr[:space_pos]
            array_name = int(expr[space_pos + 2 : bracket_open_pos])  # " pN[...]"
            alloc_size = int(expr[bracket_open_pos + 1 : bracket_close_pos])
            if array_name not in ptr_name2obj:
                value = PointerValue(array_type, alloc_size, array_name, reached)
                ptr_name2obj[array_name] = value
            else:
                value = ptr_name2obj[array_name]
                assert value.type == array_type
                value.alloc_size = alloc_size
                value.reached = reached or value.reached
        # Pointer with offset
        elif "+" in expr:
            expr, offset = expr.split("+")
            baseptr_index = int(expr[expr.rfind("*") + 2 :])
            baseptr_type = expr[: expr.rfind("*") - 1]
            if baseptr_index in ptr_name2obj:
                value = PointerOffsetValue(ptr_name2obj[baseptr_index], offset, reached)
            else:
                baseptr_obj = PointerValue(array_type, None, baseptr_index, reached)
                ptr_name2obj[baseptr_index] = baseptr_obj
                value = PointerOffsetValue(baseptr_obj, offset, reached)
        # open PTR_BEGIN
        elif expr.startswith("PTR_BEGIN"):
            value = None
            ptr_name = int(expr.split(" ")[1])
            unfinished_stack.append(ptr_name2obj[ptr_name])
        elif expr.startswith("PTR_END"):
            value = None
            ptr_name = int(expr.split(" ")[1])
            ptr_obj = ptr_name2obj[ptr_name]
            assert unfinished_stack.pop() == ptr_obj
            ptr_to_index.pop(ptr_obj)
        elif expr.startswith("PTR_IDX"):
            value = None
            ptr_index = int(expr.split(" ")[1])
            cur_ptr = None
            for obj in reversed(unfinished_stack):
                if isinstance(obj, PointerValue):
                    cur_ptr = obj
                    break
            while len(cur_ptr.value) < ptr_index + 1:
                cur_ptr.value.append(None)
            ptr_to_index[cur_ptr] = ptr_index
        elif expr.startswith("STRUCT_BEGIN"):
            value = None
            struct_type = unfinished_stack[-1].type
            unfinished_stack.append(StructValue(struct_type, reached))
        elif expr.startswith("STRUCT_END"):
            value = unfinished_stack.pop()
            # assert isinstance(value, StructValue)
            if not isinstance(value, StructValue):
                rich.print(f"[red]STRUCT_END in wrong place (Line {i + 1})[/red]")
                return None
        # primitive type
        elif re.match(
            r"^(i8|i16|i32|i64|f32|f64|func|struct|%struct|class|union)", expr
        ):
            space_pos = expr.find(" ")
            primitive_type = remove_type_prefix(expr[:space_pos])
            primitive_val = expr[space_pos + 1 :]
            if primitive_val == "?":
                primitive_val = "unknown"
            value = PrimitiveValue(primitive_val, primitive_type, reached)
        else:
            rich.print(f"[red]Unknown expression: {expr} (Line {i + 1})[/red]")
            return None

        if value is None:
            # Value is stacked to unfinished_stack (e.g. PTR_BEGIN, STRUCT_BEGIN)
            continue
        else:
            # If the stacks are not empty, add to the top of the stack
            if len(unfinished_stack) > 0:
                last_val = unfinished_stack[-1]
                if isinstance(last_val, StructValue):
                    last_val.append(value)
                elif isinstance(last_val, PointerValue):
                    try:
                        ptr_index = ptr_to_index[last_val]
                    except KeyError:
                        rich.print(
                            f"[red]PTR_IDX not found for {last_val} (Line {i+1})[/red]"
                        )
                        return None
                    last_val.value[ptr_index] = value
            else:
                parsed_args.append(value)

    to_process = Queue()
    for arg in parsed_args:
        to_process.put(arg)

    to_process.put(None)

    new_content = []
    processed = set()  # Set of visited PointerValue objects

    meet_none = False

    while not to_process.empty():
        cur = to_process.get()
        if cur is not None:
            if isinstance(cur, PointerValue):
                if cur in processed:
                    continue
                else:
                    processed.add(cur)
                    if not cur.done:
                        cur.reach_update()

            if not meet_none or cur.reached:
                new_content.append(cur.expr_string())

            for ptr_obj in cur.dependent_ptrs():
                if ptr_obj not in processed:
                    to_process.put(ptr_obj)
        else:
            meet_none = True
            # Function argument separator
            new_content.append("")

    if new_content[-1] == "":
        new_content.pop()

    return "\n".join(new_content)


def parse_carve_filename(testcase_name):
    first_undersore = testcase_name.rfind("_")
    second_underscore = testcase_name.rfind("_", 0, first_undersore)
    func_call_idx = int(testcase_name[second_underscore + 1 : first_undersore])
    # carving_idx = int(testcase_name[first_undersore + 1:])
    return testcase_name[:second_underscore], func_call_idx
