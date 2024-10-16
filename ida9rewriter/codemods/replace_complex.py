import argparse
import difflib
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple

import libcst as cst
from libcst.metadata import PositionProvider

@dataclass
class APIConfig:
    old_call_signature: str
    new_call_signature: str
    is_callable: bool

def parse_config(config: Dict[str, str]) -> List[APIConfig]:
    configs = []
    for k, v in config.items():
        is_callable = k.endswith("()")
        configs.append(APIConfig(old_call_signature=k, new_call_signature=v, is_callable=is_callable))
    return configs

CONFIG = {
    "idaapi.get_inf_structure().is_64bit()": "ida_ida.inf_is_64bit()",
    "idaapi.get_inf_structure().is_32bit()": "ida_ida.inf_is_32bit_exactly()",
    "idaapi.get_inf_structure().is_16bit()": "ida_ida.inf_is_16bit()",
    "idaapi.get_inf_structure().is_be()": "ida_ida.inf_is_be()",
    "idaapi.get_inf_structure().is_dll()": "ida_ida.inf_is_dll()",
    "idaapi.get_inf_structure().procname": "ida_ida.inf_get_procname()",
    "idaapi.get_inf_structure().max_ea": "ida_ida.inf_get_max_ea()",
    "idaapi.get_inf_structure().min_ea": "ida_ida.inf_get_min_ea()",
    "idaapi.get_inf_structure().filetype": "ida_ida.inf_get_filetype()",
    "idaapi.get_inf_structure().lflags": "ida_ida.inf_get_lflags()",
}

################################################################################

class APIReplacer(cst.CSTTransformer):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, configs: List[APIConfig]):
        super().__init__()
        self.func_configs = {config.old_call_signature: config for config in configs}
        self.references: Dict[str, List[Tuple[int, int, str]]] = {}
        self.tracked_vars: Dict[str, str] = {}

    def leave_Assign(self, original_node: cst.Assign, updated_node: cst.Assign) -> cst.RemovalSentinel:
        if len(updated_node.targets) == 1 and isinstance(updated_node.targets[0].target, cst.Name):
            var_name = updated_node.targets[0].target.value
            value = updated_node.value
            if isinstance(value, cst.Call):
                call_signature = self._get_full_name(value)
                if any(config.old_call_signature.startswith(call_signature) for config in self.func_configs.values()):
                    self.tracked_vars[var_name] = call_signature
                    # Remove the assignment since it's being replaced
                    return cst.RemoveFromParent()
        return updated_node

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.BaseExpression:
        call_signature = self._get_full_name(updated_node)
        if call_signature in self.func_configs:
            config = self.func_configs[call_signature]
            self._add_reference(call_signature, original_node, "function call")
            return self._create_replacement(config)
        return updated_node

    def leave_Attribute(self, original_node: cst.Attribute, updated_node: cst.Attribute) -> cst.BaseExpression:
        attr_signature = self._get_full_name(updated_node)
        if attr_signature in self.func_configs:
            config = self.func_configs[attr_signature]
            self._add_reference(attr_signature, original_node, "attribute access")
            return self._create_replacement(config)
        return updated_node

    def _create_replacement(self, config: APIConfig) -> cst.BaseExpression:
        return cst.parse_expression(config.new_call_signature)

    def _get_full_name(self, node: cst.BaseExpression) -> str:
        if isinstance(node, cst.Name):
            var_name = node.value
            if var_name in self.tracked_vars:
                return self.tracked_vars[var_name]
            else:
                return var_name
        elif isinstance(node, cst.Attribute):
            return f"{self._get_full_name(node.value)}.{node.attr.value}"
        elif isinstance(node, cst.Call):
            return f"{self._get_full_name(node.func)}()"
        else:
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
