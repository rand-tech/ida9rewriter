from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="ida9rewriter",
    version="0.2.0",
    author="rand0m",
    author_email="54098069+rand-tech@users.noreply.github.com",
    description="A tool to update IDA Python scripts to IDA 9.0+",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rand-tech/ida9rewriter",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ida9rewriter=ida9rewriter.cli:cli",
        ],
    },
)
