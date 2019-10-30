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
            echo "[SUCCESS] Tests results pushed"
            ;;

        d) #Docs
            echo "[BEGIN] Documentation"

            #Gen diagrams and  :
            echo "[RUNNING] pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy"
            pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy

            #Generate and publish the documentation
            if [[ ! -d mfesiem.github.io ]]; then
                echo "[RUNNING] git clone https://github.com/mfesiem/mfesiem.github.io"
                git clone https://github.com/mfesiem/mfesiem.github.io
            else
                echo "[RUNNING] cd mfesiem.github.io && git pull -v && cd .."
                cd mfesiem.github.io && git pull -v && cd ..
            fi

            folder=${OPTARG}
            if [ "$folder" = "master" ]; then
                echo "[RUNNING] pdoc3 msiempy --output-dir ./mfesiem.github.io/docs --html --force"
                rm -rf ./mfesiem.github.io/docs/msiempy/
                pdoc3 msiempy --output-dir ./mfesiem.github.io/docs --html --force
                mv ./classes.png ./mfesiem.github.io/docs/msiempy
                mv ./packages.png ./mfesiem.github.io/docs/msiempy
            else
                echo "[RUNNING] pdoc3 msiempy --output-dir ./mfesiem.github.io/docs/${folder} --html --force"
                rm -rf ./mfesiem.github.io/docs/${folder}/msiempy
                pdoc3 msiempy --output-dir ./mfesiem.github.io/docs/${folder} --html --force
                mv ./classes.png ./mfesiem.github.io/docs/${folder}/msiempy
                mv ./packages.png ./mfesiem.github.io/docs/${folder}/msiempy
            fi
            
            echo "[RUNNING] cd mfesiem.github.io && git add . && git commit -m \"Generate ${folder} docs $(date)\" && git push origin master && cd .."
            cd mfesiem.github.io && git add . && git commit -m "Generate ${folder} docs $(date)" && git push origin master && cd ..

            if [ "$folder" = "master" ]; then
                url="https://mfesiem.github.io/docs/msiempy/index.html"
            else
                url="https://mfesiem.github.io/docs/${folder}/msiempy/index.html"
            fi
            
            echo "[SUCCESS] Documentation on line at : ${url}"
            ;;

        p) ##Publish on the python index
            echo "[BEGIN] PyPI upload"
            rm -rf dist

            echo "[RUNNING] python3 setup.py build check sdist bdist_wheel"
            python3 setup.py build check sdist bdist_wheel
            
            echo "[RUNNING] twine upload --verbose dist/*"
            echo 'Dont forget to bump __version__'
            echo 'Hit ctrl+C to cancel PyPI upload'
            twine upload --verbose dist/*
            
            echo "[SUCCESS] Module published at : https://pypi.org/project/msiempy/"
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