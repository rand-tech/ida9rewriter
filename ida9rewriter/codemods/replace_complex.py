import argparse
import difflib
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple

import libcst as cst
from libcst import matchers as m
from libcst.metadata import PositionProvider


@dataclass
class APIConfig:
    old_module: str
    old_func: str
    old_attr: str
    new_module: str
    new_func: str
    is_callable: bool


def parse_config(config: Dict[str, str]) -> List[APIConfig]:
    configs = []
    for k, v in config.items():
        old_module, old_func, old_attr = k.split(":")
        new_module, new_func = v.split(":")
        is_callable = old_attr.endswith("()")
        old_attr = old_attr[:-2] if is_callable else old_attr
        new_func = new_func.rstrip("()")
        configs.append(APIConfig(old_module, old_func, old_attr, new_module, new_func, is_callable))
    return configs


CONFIG = {
    "idaapi:get_inf_structure:is_64bit()": "ida_ida:inf_is_64bit",
    "idaapi:get_inf_structure:is_32bit()": "ida_ida:inf_is_32bit_exactly",
    "idaapi:get_inf_structure:is_16bit()": "ida_ida:inf_is_16bit",
    "idaapi:get_inf_structure:is_be()": "ida_ida:inf_is_be",
    "idaapi:get_inf_structure:is_dll()": "ida_ida:inf_is_dll",
    "idaapi:get_inf_structure:procname": "ida_ida:inf_get_procname",
    "idaapi:get_inf_structure:max_ea": "ida_ida:inf_get_max_ea",
    "idaapi:get_inf_structure:min_ea": "ida_ida:inf_get_min_ea",
}

################################################################################


class APIReplacer(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, configs: List[APIConfig]):
        super().__init__()
        self.func_configs = {f"{config.old_module}.{config.old_func}": config for config in configs}
        self.attr_configs = {config.old_attr: config for config in configs}
        self.tracked_vars = {}
        self.references: Dict[str, List[Tuple[int, int, str]]] = {}

    def leave_Assign(self, original_node: cst.Assign, updated_node: cst.Assign) -> cst.Assign:
        if m.matches(updated_node.value, m.Call()):
            call_signature = self._get_call_signature(updated_node.value)
            if call_signature in self.func_configs:
                if len(updated_node.targets) == 1 and isinstance(updated_node.targets[0].target, cst.Name):
                    var_name = updated_node.targets[0].target.value
                    self.tracked_vars[var_name] = call_signature
                    self._add_reference(call_signature, original_node, "assignment")
                    return cst.RemoveFromParent()
        return updated_node

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.Call:
        if m.matches(updated_node.func, m.Attribute(value=m.Name())):
            var_name = updated_node.func.value.value
            if var_name in self.tracked_vars and updated_node.func.attr.value in self.attr_configs:
                config = self.attr_configs[updated_node.func.attr.value]
                if config.is_callable:
                    self._add_reference(f"{config.old_module}.{config.old_func}", original_node, "method call")
                    return self._create_replacement(config)
        elif m.matches(updated_node.func, m.Name()):
            call_signature = self._get_call_signature(updated_node)
            if call_signature in self.func_configs:
                config = self.func_configs[call_signature]
                self._add_reference(call_signature, original_node, "function call")
                return self._create_replacement(config)
        return updated_node

    def leave_Attribute(self, original_node: cst.Attribute, updated_node: cst.Attribute) -> cst.BaseExpression:
        if m.matches(updated_node.value, m.Name()) and updated_node.value.value in self.tracked_vars:
            if updated_node.attr.value in self.attr_configs:
                config = self.attr_configs[updated_node.attr.value]
                if not config.is_callable:
                    self._add_reference(f"{config.old_module}.{config.old_func}", original_node, "attribute access")
                    return self._create_replacement(config)
        return updated_node

    def _create_replacement(self, config: APIConfig) -> cst.Call:
        return cst.Call(
            func=cst.Attribute(
                value=cst.Name(value=config.new_module),
                attr=cst.Name(value=config.new_func),
            ),
            args=[],
        )

    def _get_call_signature(self, node: cst.Call) -> str:
        if m.matches(node.func, m.Attribute(value=m.Name())):
            return f"{node.func.value.value}.{node.func.attr.value}"
        elif m.matches(node.func, m.Name()):
            return node.func.value
        return ""

    def _add_reference(self, call_signature: str, node: cst.CSTNode, ref_type: str):
        position = self.get_metadata(PositionProvider, node).start
        self.references.setdefault(call_signature, []).append((position.line, position.column, ref_type))


def replace_api_calls(source_code: str, configs: List[APIConfig]) -> Tuple[str, Dict[str, List[Tuple[int, int, str]]]]:
    module = cst.parse_module(source_code)
    wrapper = cst.metadata.MetadataWrapper(module)
    transformer = APIReplacer(configs)
    modified_module = wrapper.visit(transformer)
    return modified_module.code, transformer.references


def bump_ida_complex(source_code: str, configs: List[APIConfig] = parse_config(CONFIG)) -> str:
    code, _ = replace_api_calls(source_code, configs)
    return code


def main():
    parser = argparse.ArgumentParser(description="Replace API calls in Python code")
    parser.add_argument("file", help="Input Python file")
    parser.add_argument("--dryrun", action="store_true", help="Print the updated code without saving it")
    args = parser.parse_args()

    configs = parse_config(CONFIG)
    with open(args.file, "r") as f:
        source_code = f.read()
    modified_code, references = replace_api_calls(source_code, configs)
    if args.dryrun:
        diff = difflib.unified_diff(source_code.splitlines(), modified_code.splitlines(), fromfile=args.file, tofile=f"{args.file} (modified)", lineterm="")
        sys.stdout.writelines("\n".join(diff))
    else:
        with open(args.file, "w") as f:
            f.write(modified_code)
        print(f"Updated {args.file}", file=sys.stderr)


if __name__ == "__main__":
    main()
