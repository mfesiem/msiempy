#!/bin/bash
#Not setting bash strict mode. See http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail
IFS=$'\n\t,'

#FUNCTIONS
usage(){
    echo "[USAGE] $0 [-h] [-t] [-d] <Folder> [-p]" 1>&2
    echo
    echo "This little script is designed to help us manage msiempy."
    echo
    echo -e "\t-h\tHelp\tPrint this help message."
    echo -e "\t-t\tTests\tLaunch tests, save output to ~/static/tests.txt and push changes to current remote branch IF SUCCESS !."
    echo -e "\t-d <folder> Docs \tPublish the docs to https://mfesiem.github.io/docs/{folder}/msiempy/"
    echo -e "\t\tuse 'master' keyword to publish to https://mfesiem.github.io/docs/msiempy/"
    echo -e "\t-p\tPyPI\tPublish to PyPI."
    
    echo 
    echo -e "\tExample : $0 -d dev -p"
    echo -e "\tGenerate the documentation to https://mfesiem.github.io/docs/{folder}/msiempy/"
    echo -e "\tand publish the module on PyPI."
    exit -1
}

while getopts ":htd:p" arg; do
    case "${arg}" in
        h) #Print help
            usage
            ;;
        t) #Run tests
            echo "[BEGIN] Testing"
            python3 setup.py test | tee ~/static/tests.txt
            echo "[RETURN CODE] $?"
            git add ~/static/tests.txt
            echo "[RETURN CODE] $?"
            git commit -m "Generate tests $(date)"
            echo "[RETURN CODE] $?"
            git push
            echo "[RETURN CODE] $?"
            echo "[IMPORTANT] Tests results pushed"
            ;;

        d) #Docs
            echo "[BEGIN] Documentation"

            #Gen diagrams and  :
            pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy
            echo "[RETURN CODE] $?"

            #Generate and publish the documentation
            if [[ ! -d mfesiem.github.io ]]; then
                git clone https://github.com/mfesiem/mfesiem.github.io
                echo "[RETURN CODE] $?"
            fi

            #mfesiem.github.io
            cd mfesiem.github.io
            echo "[RETURN CODE] $?"
            git pull -v
            echo "[RETURN CODE] $?"
            folder=${OPTARG}
            if [ "$folder" = "master" ]; then
                pdoc msiempy --output-dir ./docs --html --force
                echo "[RETURN CODE] $?"
                cp ../classes.png ./docs/msiempy
                echo "[RETURN CODE] $?"
                cp ../packages.png ./docs/msiempy
            else
                pdoc msiempy --output-dir ./docs/${folder} --html --force
                echo "[RETURN CODE] $?"
                cp ../classes.png ./docs/${folder}/msiempy
                echo "[RETURN CODE] $?"
                cp ../packages.png ./docs/${folder}/msiempy
            fi

            git add .
            git commit -m "Generate ${folder} docs $(date)"
            echo "[RETURN CODE] $?"
            git push origin master
            echo "[RETURN CODE] $?"

            cd ..

            #msiempy
            #push to current branch
            git add ./packages.png
            git add ./classes.png
            git commit -m "Generate diagrams $(date)"
            echo "[RETURN CODE] $?"
            git push
            echo "[RETURN CODE] $?"
            
            if [ "$folder" = "master" ]; then
                url="https://mfesiem.github.io/docs/msiempy/"
            else
                url="https://mfesiem.github.io/docs/${folder}/msiempy/"
            fi
            
            echo "[IMPORTANT] Documentation on line at : ${url}"
            ;;

        p) ##Publish on the python index
            echo "[BEGIN] PyPI upload"x
            rm -rf dist
            python3 setup.py build check sdist bdist_wheel
            echo "[RETURN CODE] $?"
            echo 'Dont forget to bump __version__'
            echo 'Hit ctrl+C to cancel PyPI upload'
            twine upload --verbose dist/*
            echo "[RETURN CODE] $?"
            echo "[IMPORTANT] Module published at : https://pypi.org/project/msiempy/"
            python3 setup.py clean
            ;;

        *)
            echo "[ERROR] Syntax mistake calling the script."
            usage
            exit
            ;;
    esac
done
shift $((OPTIND-1))
echo "[END] usage: $0 [-h] [-t] [-p] [-d]"