#!/bin/bash
# This shell script builds the api docs for msiempy 
# I've been running it from MacOS but I beleive it's valid on Linux too. 
# Will first write the docs under the version's folder, and then ovwewrites default (lastest). 
# See the docs files under the ./docs folder 
# See the mkdocs site under ./site folder

# Stop if errors
set -euo pipefail

# Install requirements
python3 -m pip install pydoctor mkdocs mkdocs-awesome-pages-plugin

docsfolder="./docs/$(python3 setup.py -V)"
mkdir -p "${docsfolder}"

pydoctor \
    --add-package=msiempy \
    --project-name="msiempy" \
    --html-viewsource-base="https://github.com/mfesiem/msiempy/tree/$(git rev-parse HEAD)" \
    --make-html \
    --project-base-dir="$(pwd)" \
    --docformat=restructuredtext \
    --intersphinx=https://docs.python.org/3/objects.inv \
    --html-output="${docsfolder}"

# Remove the current PyDoctor files in the top level directory
rm -f ./docs/*.html
rm -f ./docs/*.js
rm -f ./docs/*.css
rm -f ./docs/*.inv

# Generate diagrams
sudo apt-get install graphviz || sudo yum install graphviz || brew install graphviz
pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy
mv ./classes.png "${docsfolder}"
mv ./packages.png "${docsfolder}"

# Hack the mkdocs index to show msiempy version
echo "# msiempy $(python3 -c 'from msiempy import VERSION; print(VERSION)')" > "${docsfolder}/index.md"
echo "[View Documentation](msiempy.html)" >> "${docsfolder}/index.md"
echo "" >> "${docsfolder}/index.md"
echo "[Project Home](https://github.com/mfesiem/msiempy)" >> "${docsfolder}/index.md"

# Copy the docs in the versionned folder to the latest, avoid same name error on unix
if [ "$(uname)" = Linux ]; then
    find "${docsfolder}/" -type f -print0 | sort -zu | xargs -0 cp -ut "./docs" 
else
    cp -r "${docsfolder}/" "./docs"
fi

mkdocs build