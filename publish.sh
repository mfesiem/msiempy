#!/bin/bash

#Publish on the python index
python3 setup.py install --user
python3 setup.py build check sdist bdist_wheel
twine upload --verbose dist/*
python3 setup.py clean

#Generate and publish the documentation
git clone https://github.com/mfesiem/mfesiem.github.io
pdoc msiempy --output-dir ./mfesiem.github.io/docs --html --force
pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy
mv ./classes.png ./mfesiem.github.io/docs/msiempy
mv ./packages.png ./mfesiem.github.io/docs/msiempy
cd mfesiem.github.io
git add .
git commit -m "Generate docs $(date)"
git push origin master
cd ..
rm -rf mfesiem.github.io
