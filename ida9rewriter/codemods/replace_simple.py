import os
import sys

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
}

################################################################################


class IDAAPIUpdater(VisitorBasedCodemodCommand):
    def __init__(self, context: CodemodContext):
        super().__init__(context)
        self.import_aliases = {}
        self.glob_imports = set()

    def visit_Import(self, node: cst.Import) -> None:
        for alias in node.names:
            asname = alias.asname.name.value if alias.asname else alias.name.value
            self.import_aliases[asname] = alias.name.value

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        module_name = self._get_module_name(node.module) if node.module else ''
        if isinstance(node.names, cst.ImportStar):
            self.glob_imports.add(module_name)
        else:
            for alias in node.names:
                asname = alias.asname.name.value if alias.asname else alias.name.value
                full_name = f"{module_name}.{alias.name.value}".lstrip('.')
                self.import_aliases[asname] = full_name

    def leave_Attribute(self, original_node: cst.Attribute, updated_node: cst.Attribute) -> cst.BaseExpression:
        full_name = self._get_full_name(updated_node)
        if (new_full_name := REPLACEMENTS.get(full_name)):
            return self._construct_attribute(new_full_name)
        return updated_node

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.Call:
        full_name = None
        if isinstance(updated_node.func, cst.Attribute):
            full_name = self._get_full_name(updated_node.func)
        elif isinstance(updated_node.func, cst.Name):
            func_name = updated_node.func.value
            full_name = self.import_aliases.get(func_name, func_name)

        if (new_func := REPLACEMENTS.get(full_name)):
            return self._replace_func(updated_node, new_func)
        return updated_node

    def leave_FunctionDef(self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef) -> cst.FunctionDef:
        if updated_node.name.value == "construct_macro":
            new_params = [
                cst.Param(name=cst.Name("self")),
                cst.Param(name=cst.Name("insn"), annotation=cst.Annotation(cst.Name("insn_t"))),
                cst.Param(name=cst.Name("enable"), annotation=cst.Annotation(cst.Name("bool"))),
            ]
            return updated_node.with_changes(params=cst.Parameters(new_params), returns=cst.Annotation(cst.Name("bool")))
        return updated_node

    def _get_module_name(self, module: cst.BaseExpression) -> str:
        if isinstance(module, cst.Name):
            return module.value
        elif isinstance(module, cst.Attribute):
            return self._get_full_name(module)
        return ''

    def _get_full_name(self, node: cst.Attribute|cst.Name) -> str:
        assert isinstance(node, cst.Attribute) or isinstance(node, cst.Name), f"Expected Attribute, got {type(node)} instead"
        parts = []
        while isinstance(node, cst.Attribute):
            parts.append(node.attr.value)
            node = node.value
        if isinstance(node, cst.Name):
            parts.append(node.value)
        else:
            return ""
        assert all(isinstance(part, str) for part in parts)
        full_name = parts[::-1]
        resolved_first_part = self.import_aliases.get(full_name[0], '.'.join(full_name))
        if not isinstance(resolved_first_part, str):
            resolved_first_part = self._get_full_name(resolved_first_part)
        full_name = [resolved_first_part] + list(full_name)[1:]
        return '.'.join(full_name)

    @staticmethod
    def _construct_attribute(full_name: str) -> cst.BaseExpression:
        parts = full_name.split(".")
        node = cst.Name(parts[0])
        for part in parts[1:]:
            node = cst.Attribute(value=node, attr=cst.Name(part))
        return node

    def _replace_func(self, node: cst.Call, new_func: str) -> cst.Call:
        new_func_node = self._construct_attribute(new_func)
        return node.with_changes(func=new_func_node)

def bump_ida_simple(source_code: str) -> str:
    module = cst.parse_module(source_code)
    context = CodemodContext()
    transformer = IDAAPIUpdater(context)
    modified_module = module.visit(transformer)
    return modified_module.code


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
