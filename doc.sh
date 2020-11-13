#!/bin/bash
# This shell script builds the api docs for msiempy 
# I've been running it from MacOS but I beleive it's valid on Linux too. 
# Will first write the docs under the version's folder, and then ovwewrites default (lastest). 
# See the docs files under the ./docs folder or the 1rst CLI argument
# See the mkdocs site under ./site folder

# Requirements: graphviz, pydoctor mkdocs mkdocs-awesome-pages-plugin
# sudo apt-get install graphviz || sudo yum install graphviz || brew install graphviz

# Stop if errors
set -euo pipefail

# ./docs
docs=${1:-"./docs"}    

# Install python requirements
python3 setup.py install
python3 -m pip install -r requirements.txt
python3 -m pip install pydoctor mkdocs mkdocs-awesome-pages-plugin

docsfolder="${docs}/$(python3 setup.py -V)"
mkdir -p "${docsfolder}"

# Run pydoctor build

pydoctor \
    --add-package=msiempy \
    --project-name="msiempy" \
    --html-viewsource-base="https://github.com/mfesiem/msiempy/tree/$(git rev-parse HEAD)" \
    --make-html \
    --project-base-dir="$(pwd)" \
    --docformat=restructuredtext \
    --intersphinx=https://docs.python.org/3/objects.inv \
    --html-output="${docsfolder}"

# Generate diagrams

pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy

mv ./classes.png "${docsfolder}"
mv ./packages.png "${docsfolder}"

# Hack the mkdocs index to show msiempy version

project_version="$(python3 -c 'from msiempy import VERSION; print(VERSION)')"

echo "# msiempy ${project_version}" > "${docsfolder}/index.md"
echo "[View Documentation](msiempy.html)" >> "${docsfolder}/index.md"
echo "" >> "${docsfolder}/index.md"
echo "[Project Home](https://github.com/mfesiem/msiempy)" >> "${docsfolder}/index.md"

# Copy the docs in the versionned folder to the latest
cp -rf ${docsfolder}/* "${docs}"

# Run mkdocs build
mkdocs build