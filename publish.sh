pdoc msiempy --output-dir ./docs/mfesiem.github.oi/ --html
cd ./docs/mfesiem.github.oi/
git add .
git commit -m 'Generate docs'
git push origin master
cd ../../
pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy
mv ./classes.png ./docs
mv ./packages,png ./docs
