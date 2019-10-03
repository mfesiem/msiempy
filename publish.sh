#!/bin/bash
### CODE COPIED ###
# Created by Jamie Cruwys on 21/02/2014.
symbol="*"
paddingSymbol=" "
lineLength=70
charsToOption=1
charsToName=3
function generatePadding() {
    string="";
    for (( i=0; i < $2; i++ )); do
        string+="$1";
    done
    echo "$string";
}
remainingLength=$(( $lineLength - 2 ));
line=$(generatePadding "${symbol}" "${lineLength}");
toOptionPadding=$(generatePadding "${paddingSymbol}" "${charsToOption}");
toNamePadding=$(generatePadding "$paddingSymbol" "$charsToName");
function generateText() {
    totalCharsToPad=$((remainingLength - ${#1}));
    charsToPadEachSide=$((totalCharsToPad / 2));
    padding=$(generatePadding "$paddingSymbol" "$charsToPadEachSide");
    totalChars=$(( ${#symbol} + ${#padding} + ${#1} + ${#padding} + ${#symbol} ));
    if [[ ${totalChars} < ${lineLength} ]]; then
        echo "${symbol}${padding}${1}${padding}${paddingSymbol}${symbol}";
    else
        echo "${symbol}${padding}${1}${padding}${symbol}";
    fi
}
function generateSubTitle() {  
    echo "$line"
    generateText "$1"
    echo "$line"
}
### END CODE COPIED ###

#Setting bash strict mode. See http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail
IFS=$'\n\t,'

#FUNCTIONS
usage(){
    generateSubTitle "Usage"
    echo "Usage: $0 [-h] [-t] [-p] [-d]" 1>&2
    echo
    echo "This little script is designed to help us manage msiempy."
    echo "Arguments should be passed to the script in the same order they are listed in this"
    echo "message to avoid unexpected behaviours."
    echo
    echo -e "\t-h\t\tPrint this help message."
    echo -e "\t-t\t\tLaunch tests, save output to ~/static/tests.txt and push changes to current remote branch."
    echo -e "\t-p\t\tPublish to PYPI."
    echo -e "\t-d\t\tPublish the docs to https://mfesiem.github.io/docs/msiempy/"
    exit -1
}

while getopts ":htpd" arg; do
    case "${arg}" in
        h) #Print help
            usage
            ;;
        t) #Run tests
            generateSubTitle "Testing"
            python3 setup.py test | tee ~/static/tests.txt
            git add ~/static/tests.txt
            git commit -m "Generate tests $(date)"
            git push
            ;;

        p) ##Publish on the python index
            generateSubTitle "PyPI upload"x
            rm -rf dist
            python3 setup.py build check sdist bdist_wheel
            echo 'HIT CTRL+C TO CANCEL PYPI DISTRIBUTION UPLOAD'
            twine upload --verbose dist/*
            python3 setup.py clean
            ;;

        d) #Docs
            generateSubTitle "Documentation"
            #Generate and publish the documentation
            git clone https://github.com/mfesiem/mfesiem.github.io
            pdoc msiempy --output-dir ./mfesiem.github.io/docs --html --force
            pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy
            mv ./classes.png ./mfesiem.github.io/docs/msiempy
            mv ./packages.png ./mfesiem.github.io/docs/msiempy
            cd mfesiem.github.io
            git add .
            git commit -m "Generate docs $(date)"
            git push
            cd ..
            rm -rf mfesiem.github.io

            ;;
        *)
            generateSubTitle "Syntax mistake"
            echo "[ERROR] You made a syntax mistake calling the script."
            usage
            exit
    esac
done
shift $((OPTIND-1))
generateSubTitle "End, usage: $0 [-h] [-t] [-p] [-d]"