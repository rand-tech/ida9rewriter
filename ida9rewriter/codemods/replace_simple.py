import os
import sys
from typing import List, Set, Dict, Tuple

import libcst as cst
from libcst.codemod import CodemodContext, VisitorBasedCodemodCommand

REPLACEMENTS = {
    # ida_struct replacements
    "ida_struct.add_struc": "idc.add_struc",
    "ida_struct.add_struc_member": "idc.add_struc_member",
    "ida_struct.del_struc": "idc.del_struc",
    "ida_struct.del_struc_member": "idc.del_struc_member",
    "ida_struct.expand_struc": "idc.expand_struc",
    "ida_struct.get_member_cmt": "idc.get_member_cmt",
    "ida_struct.get_member_id": "idc.get_member_id",
    "ida_struct.get_member_name": "idc.get_member_name",
    "ida_struct.get_member_size": "idc.get_member_size",
    "ida_struct.get_struc_cmt": "idc.get_struc_cmt",
    "ida_struct.get_struc_id": "idc.get_struc_id",
    "ida_struct.get_struc_name": "idc.get_struc_name",
    "ida_struct.get_struc_size": "idc.get_struc_size",
    "ida_struct.is_member_id": "idc.is_member_id",
    "ida_struct.is_union": "idc.is_union",
    "ida_struct.set_member_cmt": "idc.set_member_cmt",
    "ida_struct.set_member_name": "idc.set_member_name",
    "ida_struct.set_member_type": "idc.set_member_type",
    "ida_struct.set_struc_cmt": "idc.set_struc_cmt",
    "ida_struct.set_struc_name": "idc.set_struc_name",
    # idk (learned from IDArling)
    "ida_struct.get_struc": "idc.get_struc",
    "ida_struct.get_member_by_name": "idc.get_member_by_name",
    "ida_struct.get_member_by_fullname": "idc.get_member_by_fullname",
    "ida_struct.retrieve_member_info": "idc.retrieve_member_info",
    # ida_enum replacements
    "ida_enum.add_enum": "idc.add_enum",
    "ida_enum.add_enum_member": "idc.add_enum_member",
    "ida_enum.del_enum": "idc.del_enum",
    "ida_enum.del_enum_member": "idc.del_enum_member",
    "ida_enum.get_bmask_cmt": "idc.get_bmask_cmt",
    "ida_enum.get_bmask_name": "idc.get_bmask_name",
    "ida_enum.get_enum": "idc.get_enum",
    "ida_enum.get_enum_cmt": "idc.get_enum_cmt",
    "ida_enum.get_enum_flag": "idc.get_enum_flag",
    "ida_enum.get_enum_member": "idc.get_enum_member",
    "ida_enum.get_enum_member_bmask": "idc.get_enum_member_bmask",
    "ida_enum.get_enum_member_by_name": "idc.get_enum_member_by_name",
    "ida_enum.get_enum_member_cmt": "idc.get_enum_member_cmt",
    "ida_enum.get_enum_member_enum": "idc.get_enum_member_enum",
    "ida_enum.get_enum_member_name": "idc.get_enum_member_name",
    "ida_enum.get_enum_member_value": "idc.get_enum_member_value",
    "ida_enum.get_enum_name": "idc.get_enum_name",
    "ida_enum.get_enum_size": "idc.get_enum_size",
    "ida_enum.get_enum_width": "idc.get_enum_width",
    "ida_enum.get_first_bmask": "idc.get_first_bmask",
    "ida_enum.get_first_enum_member": "idc.get_first_enum_member",
    "ida_enum.get_last_bmask": "idc.get_last_bmask",
    "ida_enum.get_last_enum_member": "idc.get_last_enum_member",
    "ida_enum.get_next_bmask": "idc.get_next_bmask",
    "ida_enum.get_next_enum_member": "idc.get_next_enum_member",
    "ida_enum.get_prev_bmask": "idc.get_prev_bmask",
    "ida_enum.get_prev_enum_member": "idc.get_prev_enum_member",
    "ida_enum.is_bf": "idc.is_bf",
    "ida_enum.set_bmask_cmt": "idc.set_bmask_cmt",
    "ida_enum.set_bmask_name": "idc.set_bmask_name",
    "ida_enum.set_enum_bf": "idc.set_enum_bf",
    "ida_enum.set_enum_cmt": "idc.set_enum_cmt",
    "ida_enum.set_enum_flag": "idc.set_enum_flag",
    "ida_enum.set_enum_member_cmt": "idc.set_enum_member_cmt",
    "ida_enum.set_enum_member_name": "idc.set_enum_member_name",
    "ida_enum.set_enum_name": "idc.set_enum_name",
    "ida_enum.set_enum_width": "idc.set_enum_width",
    # idk (learned from IDArling)
    "ida_enum.get_enum_idx": "idc.get_enum_idx",
    "ida_enum.get_enum_member_serial": "idc.get_enum_member_serial",
    #  other stuff
    "ida_bytes.get_octet2": "ida_bytes.get_octet",
    "ida_graph.abstract_graph_t": "ida_graph.drawable_graph_t",
    "ida_graph.mutable_graph_t": "ida_graph.interactive_graph_t",
    "ida_graph.create_mutable_graph": "ida_graph.create_interactive_graph",
    "ida_graph.delete_mutable_graph": "ida_graph.delete_interactive_graph",
    "ida_graph.grcode_create_mutable_graph": "ida_graph.grcode_create_interactive_graph",
    "ida_ua.construct_macro2": "ida_ua.construct_macro",
    "idaapi.cvar.inf.is_be": "ida_ida.inf_is_be",
    "idaapi.is_align_insn": "ida_ida.is_align_insn",
    "idaapi.get_item_head": "idc.get_item_head",
    "idaapi.del_items": "idc.del_items",
    # diaphora
    "idc.get_ordinal_qty": "idaapi.get_ordinal_count",
    #
    "ida_dirtree.DIRTREE_STRUCTS": "ida_dirtree.DIRTREE_LOCAL_TYPES",
    "ida_dirtree.DIRTREE_ENUMS": "ida_dirtree.DIRTREE_LOCAL_TYPES",
    "ida_dirtree.DIRTREE_STRUCTS_BOOKMARKS": "ida_dirtree.DIRTREE_LTYPES_BOOKMARKS",
    "ida_dirtree.DIRTREE_ENUMS_BOOKMARKS": "ida_dirtree.DIRTREE_LTYPES_BOOKMARKS",
}

################################################################################
class IDAAPIUpdater(VisitorBasedCodemodCommand):
    def __init__(self, context: CodemodContext):
        super().__init__(context)
        self.import_aliases = {}         # alias → full module (e.g. "idc")
        self.import_from_names = {}      # imported name → full module.name
        self.glob_imports: Set[str] = set()
        self.required_imports: Set[str] = set()
        self.existing_imports: Set[str] = set()  # Track which modules are already imported
        self.used_names: Set[str] = set()  # Track all names used in the code

        self.module_functions_used = {}    # module → set of functions used
        self.module_functions_replaced = {} # module → set of functions replaced

        self.star_imported_funcs_replaced: Dict[str, Set[str]] = {}  # module → set of star-imported func names replaced

    def visit_Import(self, node: cst.Import) -> None:
        for alias in node.names:
            module_name = alias.name.value
            asname = alias.asname.name.value if alias.asname else module_name
            self.import_aliases[asname] = module_name
            self.existing_imports.add(module_name)

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        module = ""
        if node.module:
            # e.g. "from idc import *" or "from idc import add_struc"
            module = node.module.value
            self.existing_imports.add(module)

        if isinstance(node.names, cst.ImportStar):
            self.glob_imports.add(module)
        else:
            for alias in node.names:
                name = alias.name.value
                asname = alias.asname.name.value if alias.asname else name
                self.import_from_names[asname] = f"{module}.{name}".lstrip(".")

    def visit_Name(self, node: cst.Name) -> None:
        self.used_names.add(node.value)
        if node.value in self.import_from_names:
            full_name = self.import_from_names[node.value]
            mod = full_name.split(".", 1)[0]
            if mod not in self.module_functions_used:
                self.module_functions_used[mod] = set()
            self.module_functions_used[mod].add(full_name)

    def leave_Attribute(
        self, original_node: cst.Attribute, updated_node: cst.Attribute
    ) -> cst.BaseExpression:
        full = self._get_full_name(updated_node)
        if any(
            key.startswith(full + ".")
            for key in REPLACEMENTS
            if key.split(".", 1)[0] == full.split(".", 1)[0]
        ):
            return updated_node

        parts = full.split(".")
        if len(parts) > 1:
            mod = parts[0]
            if mod not in self.module_functions_used:
                self.module_functions_used[mod] = set()
            self.module_functions_used[mod].add(full)

        if full in REPLACEMENTS:
            new_full = REPLACEMENTS[full]
            mod = new_full.split(".", 1)[0]
            self.required_imports.add(mod)

            orig_mod = full.split(".", 1)[0]
            if orig_mod not in self.module_functions_replaced:
                self.module_functions_replaced[orig_mod] = set()
            self.module_functions_replaced[orig_mod].add(full)

            return self._construct_attribute(new_full)
        return updated_node

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.Call:
        func_name = None
        full = None

        if isinstance(updated_node.func, cst.Attribute):
            full = self._get_full_name(updated_node.func)
        elif isinstance(updated_node.func, cst.Name):
            func_name = updated_node.func.value
            self.used_names.add(func_name)

            if func_name in self.import_from_names:
                full = self.import_from_names[func_name]

                mod = full.split(".", 1)[0]
                if mod not in self.module_functions_used:
                    self.module_functions_used[mod] = set()
                self.module_functions_used[mod].add(full)
            else:
                for mod in self.glob_imports:
                    potential_full = f"{mod}.{func_name}"
                    if potential_full in REPLACEMENTS:
                        full = potential_full
                        if mod not in self.star_imported_funcs_replaced:
                            self.star_imported_funcs_replaced[mod] = set()
                        self.star_imported_funcs_replaced[mod].add(func_name)
                        break

                if not full:
                    full = self.import_aliases.get(func_name, func_name)

        if full and (new_full := REPLACEMENTS.get(full)):
            module = new_full.split(".")[0]
            self.required_imports.add(module)

            if full:
                orig_mod = full.split(".", 1)[0]
                if orig_mod not in self.module_functions_replaced:
                    self.module_functions_replaced[orig_mod] = set()
                self.module_functions_replaced[orig_mod].add(full)

            return self._replace_func(updated_node, new_full)
        return updated_node

    def leave_Module(self, original_node: cst.Module, updated_node: cst.Module) -> cst.Module:
        modules_to_keep = set()
        modules_to_remove = set()

        needed_imports = set(self.required_imports)

        for mod in self.module_functions_used:
            used_funcs = self.module_functions_used.get(mod, set())
            replaced_funcs = self.module_functions_replaced.get(mod, set())

            if used_funcs and not used_funcs.issubset(replaced_funcs):
                modules_to_keep.add(mod)
            elif used_funcs and used_funcs.issubset(replaced_funcs):
                modules_to_remove.add(mod)

        for mod in self.glob_imports:
            if mod in self.star_imported_funcs_replaced and mod not in modules_to_keep:
                modules_to_remove.add(mod)
            else:
                modules_to_keep.add(mod)

        modules_to_keep.update(needed_imports)

        to_add: List[cst.SimpleStatementLine] = []
        for mod in sorted(needed_imports):
            if mod not in self.existing_imports:
                imp = cst.Import([cst.ImportAlias(name=cst.Name(mod))])
                to_add.append(cst.SimpleStatementLine([imp]))

        filtered_body = []
        for stmt in updated_node.body:
            keep_stmt = True

            if isinstance(stmt, cst.SimpleStatementLine) and len(stmt.body) == 1:
                if isinstance(stmt.body[0], cst.Import):
                    import_stmt = stmt.body[0]
                    new_names = []

                    for alias in import_stmt.names:
                        module_name = alias.name.value
                        if module_name in modules_to_keep:
                            new_names.append(alias)
                        elif module_name in modules_to_remove:
                            continue
                        else:
                            new_names.append(alias)
                    if not new_names:
                        keep_stmt = False
                    elif len(new_names) != len(import_stmt.names):
                        stmt = stmt.with_changes(
                            body=[import_stmt.with_changes(names=new_names)]
                        )

                elif isinstance(stmt.body[0], cst.ImportFrom):
                    from_import = stmt.body[0]
                    module_name = from_import.module.value if from_import.module else ""

                    if isinstance(from_import.names, cst.ImportStar):
                        if module_name in modules_to_remove:
                            keep_stmt = False
                    else:
                        if module_name in modules_to_remove:
                            keep_stmt = False
                        else:
                            new_names = []
                            for alias in from_import.names:
                                name = alias.name.value
                                full_name = f"{module_name}.{name}"
                                if full_name in REPLACEMENTS:
                                    print(f'{full_name = }, {full_name in REPLACEMENTS}')
                                    continue
                                else:
                                    new_names.append(alias)

                            if not new_names:
                                keep_stmt = False
                            elif len(new_names) != len(from_import.names):
                                stmt = stmt.with_changes(
                                    body=[from_import.with_changes(names=new_names)]
                                )

            if keep_stmt:
                filtered_body.append(stmt)

        insert_at = 0
        if (
            filtered_body
            and isinstance(filtered_body[0], cst.SimpleStatementLine)
            and isinstance(filtered_body[0].body[0], cst.Expr)
            and isinstance(filtered_body[0].body[0].value, cst.SimpleString)
        ):
            insert_at = 1

        new_body = filtered_body[:insert_at] + to_add + filtered_body[insert_at:]
        return updated_node.with_changes(body=new_body)

    def _get_full_name(self, node: cst.Attribute|cst.Name) -> str:
        assert isinstance(node, cst.Attribute) or isinstance(node, cst.Name), f"Expected Attribute, got {type(node)} instead"
        parts = []
        while isinstance(node, cst.Attribute):
            parts.append(node.attr.value)
            node = node.value
        if isinstance(node, cst.Name):
            name = node.value
            parts.append(name)
            self.used_names.add(name)
        else:
            return ""
        parts.reverse()
        first = parts[0]

        if first in self.import_aliases:
            resolved = self.import_aliases[first]
            parts[0] = resolved
        elif first in self.import_from_names:
            full_path = self.import_from_names[first]
            module_parts = full_path.split(".")
            parts[0] = module_parts[0]
            if len(module_parts) > 1:
                parts.insert(1, module_parts[1])

        return ".".join(parts)

    @staticmethod
    def _construct_attribute(full: str) -> cst.BaseExpression:
        parts = full.split(".")
        node: cst.BaseExpression = cst.Name(parts[0])
        for attr in parts[1:]:
            node = cst.Attribute(value=node, attr=cst.Name(attr))
        return node

    def _replace_func(self, call: cst.Call, full: str) -> cst.Call:
        # rebuild the .func
        new_func = self._construct_attribute(full)
        return call.with_changes(func=new_func)


def bump_ida_simple(source_code: str) -> str:
    module = cst.parse_module(source_code)
    transformer = IDAAPIUpdater(CodemodContext())
    modified = module.visit(transformer)

    code = modified.code
    lines = code.splitlines()

    last_import_idx = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            last_import_idx = i

    if last_import_idx >= 0 and last_import_idx + 1 < len(lines):
        if lines[last_import_idx + 1].strip() != "":
            lines.insert(last_import_idx + 1, "")

    trailing_newline = "\n" if code.endswith("\n") else ""
    return "\n".join(lines) + trailing_newline

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Update IDA API calls in a Python script.")
    parser.add_argument("input", type=str, help="Input Python script")
    parser.add_argument("--dryrun", action="store_true", help="Print the updated code without saving it")
    args = parser.parse_args()
    if not os.path.exists(args.input):
        print(f"File not found: {args.input}", file=sys.stderr)
        exit(1)

    with open(args.input, "r") as f:
        old_code = f.read()
    updated_code = bump_ida_simple(old_code)
    if args.dryrun:
        import difflib

        diff = difflib.unified_diff(old_code.splitlines(), updated_code.splitlines(), lineterm="")
        print("\n".join(diff))
    else:
        with open(args.input, "w") as f:
            f.write(updated_code)
        print(f"Updated {args.input}")
