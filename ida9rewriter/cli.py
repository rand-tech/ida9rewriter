import argparse
import difflib
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

from tqdm import tqdm

from ida9rewriter.codemods.replace_complex import bump_ida_complex
from ida9rewriter.codemods.replace_simple import bump_ida_simple


def bump_ida(source_code: str) -> str:
    passes = [bump_ida_complex, bump_ida_simple]
    for pass_ in passes:
        source_code = pass_(source_code)
    return source_code


def process_file(file: str, is_dryrun: bool):
    with open(file, "r") as f:
        source_code = f.read()
    new_source = bump_ida(source_code)
    if is_dryrun:
        diff = list(difflib.unified_diff(source_code.splitlines(), new_source.splitlines(), fromfile=file, tofile=f"{file} (modified)", lineterm=""))
        if diff:
            return file, "\n".join(diff)
    else:
        with open(file, "w") as f:
            f.write(new_source)
    return file, None


def run(source: str, is_dryrun: bool, recursive: bool):
    if os.path.isdir(source):
        if not recursive:
            print(f"Error: {source} is a directory. Use -r/--recursive to rewrite all Python files in the directory.", file=sys.stderr)
            exit(1)
        files = [os.path.join(root, file) for root, _, files in os.walk(source) for file in files if file.endswith(".py")]
    else:
        files = [source]

    results = {}
    total_files = len(files)

    with ProcessPoolExecutor() as executor:
        futures = {executor.submit(process_file, file, is_dryrun): file for file in files}
        with tqdm(total=total_files, desc="Processing files", unit="file") as pbar:
            for future in as_completed(futures):
                file, result = future.result()
                if result:
                    results[file] = result
                pbar.update(1)
    if results:
        print("\nModified files:")
        for file in sorted(results.keys()):
            print(f"\nFile: {file}")
            print(results[file])
    else:
        print("\nNo files were modified.")


def cli():
    parser = argparse.ArgumentParser(description="Rewrite IDA Pro API calls")
    parser.add_argument("source", help="Path to the source file/directory")
    parser.add_argument("-d", "--dryrun", action="store_true", help="Print the updated code without saving it", default=False)
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively rewrite all Python files in the directory", default=False)
    args = parser.parse_args()
    run(args.source, args.dryrun, args.recursive)


if __name__ == "__main__":
    cli()
