import argparse
import difflib
import sys
import os

from ida9rewriter.codemods.replace_complex import bump_ida_complex
from ida9rewriter.codemods.replace_simple import bump_ida_simple


def bump_ida(source_code: str) -> str:
    passes = [bump_ida_complex, bump_ida_simple]
    for pass_ in passes:
        source_code = pass_(source_code)
    return source_code


def run(file: str, is_dryrun: bool):
    with open(file, "r") as f:
        source_code = f.read()

    new_source = bump_ida(source_code)
    if is_dryrun:
        diff = difflib.unified_diff(source_code.splitlines(), new_source.splitlines(), fromfile=file, tofile=f"{file} (modified)", lineterm="")
        sys.stdout.write("\n".join(diff) + "\n" * 3)
    else:
        with open(file, "w") as f:
            f.write(new_source)


def cli():
    parser = argparse.ArgumentParser(description="Rewrite IDA Pro API calls")
    parser.add_argument("source", help="Path to the source file/directory")
    parser.add_argument("-d", "--dryrun", action="store_true", help="Print the updated code without saving it", default=True)
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively rewrite all Python files in the directory", default=False)

    args = parser.parse_args()
    if os.path.isdir(args.source) and not args.recursive:
        print(f"Error: {args.source} is a directory. Use -r/--recursive to rewrite all Python files in the directory.", file=sys.stderr)
        exit(1)
    if args.recursive:
        for root, _, files in os.walk(args.source):
            for file in files:
                if file.endswith(".py"):
                    run(os.path.join(root, file), args.dryrun)
    else:
        run(args.source, args.dryrun)


if __name__ == "__main__":
    cli()
