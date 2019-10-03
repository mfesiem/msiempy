#!/bin/bash
### CODE COPIED ###
# Created by Jamie Cruwys on 21/02/2014.
symbol="#"
paddingSymbol=" "
lineLength=120
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
#set -euo pipefail
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
    echo -e "\t-t\t\tLaunch tests, save output to ~/static/tests.txt and push changes to current remote branch IF SUCCESS !."
    echo -e "\t-p\t\tPublish to PYPI."
    echo -e "\t-d <Folder>\t\tPublish the docs to https://mfesiem.github.io/docs/{folder}/msiempy/"
    echo -e "\t\tuse 'master' keyword to publish to https://mfesiem.github.io/docs/msiempy/"
    exit -1
}

while getopts ":htpd:" arg; do
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
            #echo "[IMPORTANT] Tests pushed"
            ;;

        p) ##Publish on the python index
            generateSubTitle "PyPI upload"x
            rm -rf dist
            python3 setup.py build check sdist bdist_wheel
            echo 'Dont forget to bump __version__'
            echo 'Hit ctrl+C to cancel PyPI upload'
            twine upload --verbose dist/*
            python3 setup.py clean
            ;;

        d) #Docs
            generateSubTitle "Documentation"

            #Gen diagrams and  :
            pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy

            #Generate and publish the documentation
            if [[ ! -d mfesiem.github.io ]]; then
                git clone https://github.com/mfesiem/mfesiem.github.io
            fi

            #mfesiem.github.io
            cd mfesiem.github.io
            git pull -v
            folder=${OPTARG}
            if [ "$folder" = "master" ]; then
                pdoc msiempy --output-dir ./docs --html --force
                cp ../classes.png ./docs/msiempy
                cp ../packages.png ./docs/msiempy
            else
                pdoc msiempy --output-dir ./docs/${folder} --html --force
                cp ../classes.png ./docs/${folder}/msiempy
                cp ../packages.png ./docs/${folder}/msiempy
            fi

            git add .
            git commit -m "Generate ${folder} docs $(date)"
            git push origin master

            cd ..

            #msiempy
            #push to current branch
            git add .
            git commit -m "Generate diagrams $(date)"
            git push
            
            if [ "$folder" = "master" ]; then
                url="https://mfesiem.github.io/docs/msiempy/"
            else
                url="https://mfesiem.github.io/docs/${folder}/msiempy/"
            fi
            
            echo "[IMPORTANT] Documentation on line at : ${url}"
            ;;
        *)
            generateSubTitle "Syntax mistake"
            echo "[ERROR] You made a syntax mistake calling the script."
            usage
            exit
            ;;
    esac
done
shift $((OPTIND-1))
echo "[END] usage: $0 [-h] [-t] [-p] [-d]"