import os
from setuptools import setup
import toml

# Read the configuration from pyproject.toml
with open("pyproject.toml", "r") as pyproject_file:
    config = toml.load(pyproject_file)

# Get the CSTRUCT_BRANCH environment variable
cstruct_branch = os.getenv("CSTRUCT_BRANCH", "main")

# Override the cstruct dependency
dependencies = config["project"]["dependencies"]
dependencies = [
    f"dissect.cstruct @ git+https://github.com/fox-it/dissect.cstruct@{cstruct_branch}" 
    if "dissect.cstruct" in dep else dep
    for dep in dependencies
]

print(dependencies)

# Setup the package
setup(
    name=config["project"]["name"],
    description=config["project"]["description"],
    long_description=open(config["project"]["readme"]).read(),
    long_description_content_type="text/markdown",
    author=config["project"]["authors"][0]["name"],
    author_email=config["project"]["authors"][0]["email"],
    url=config["project"]["urls"]["homepage"],
    classifiers=config["project"]["classifiers"],
    python_requires=config["project"]["requires-python"],
    install_requires=dependencies,
    packages=["dissect.target"],
    include_package_data=True,
)
