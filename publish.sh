#!/bin/bash
#Not setting bash strict mode. See http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail
IFS=$'\n\t,'

usage(){
    echo "[USAGE] $0 [-h] [-p] <test/master/other>" 1>&2
    echo
    echo "Help us publish msiempy on the internet."
    echo
    echo -e "\t-h\tPrint this help message."
    echo -e "\t-p\t<keyword>\tGenerate documentation and publish to PyPi."
    echo -e "\t\tuse 'master' keyword to publish to production PyPi and docs to https://mfesiem.github.io/docs/msiempy/"
    echo -e "\t\tuse 'test' keyword to publish to test PyPi and docs to https://mfesiem.github.io/docs/test/msiempy/"
    echo -e "\t\tuse whatever other keyword to publish only the docs to https://mfesiem.github.io/docs/{keyword}/msiempy/"
    echo 
    echo -e "\tExample : $0 -p test"
    echo -e "\t\tGenerate the documentation to https://mfesiem.github.io/docs/test/msiempy/"
    echo -e "\t\tand publish the module on test PyPI."
    echo
    echo -e "\tExample : $0 -p master"
    echo -e "\t\tGenerate the documentation to https://mfesiem.github.io/docs//msiempy/"
    echo -e "\t\tand publish the module on PyPI."
    echo
    echo -e "\tExample : $0 -p dev"
    echo -e "\t\tOnly generate the documentation to https://mfesiem.github.io/docs/dev/msiempy/"
    exit -1
}

while getopts ":hp:" arg; do
    case "${arg}" in
        h) #Print help
            usage
            ;;

        p) ##Publish on the python index
            echo "[BEGIN] Documentation upload"

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

            keyword=${OPTARG}
            if [ "$keyword" = "master" ]; then
                echo "[RUNNING] pdoc3 msiempy --output-dir ./mfesiem.github.io/docs --html --force"
                rm -rf ./mfesiem.github.io/docs/msiempy/
                pdoc3 msiempy --output-dir ./mfesiem.github.io/docs --html --force
                mv ./classes.png ./mfesiem.github.io/docs/msiempy
                mv ./packages.png ./mfesiem.github.io/docs/msiempy
            else
                echo "[RUNNING] pdoc3 msiempy --output-dir ./mfesiem.github.io/docs/${keyword} --html --force"
                rm -rf ./mfesiem.github.io/docs/${keyword}/msiempy
                pdoc3 msiempy --output-dir ./mfesiem.github.io/docs/${keyword} --html --force
                mv ./classes.png ./mfesiem.github.io/docs/${keyword}/msiempy
                mv ./packages.png ./mfesiem.github.io/docs/${keyword}/msiempy
            fi
            
            echo "[RUNNING] cd mfesiem.github.io && git add . && git commit -m \"Generate ${keyword} docs $(date)\" && git push origin master && cd .."
            cd mfesiem.github.io && git add . && git commit -m "Generate ${keyword} docs $(date)" && git push origin master && cd ..

            if [ "$keyword" = "master" ]; then
                url="https://mfesiem.github.io/docs/msiempy/index.html"
            else
                url="https://mfesiem.github.io/docs/${keyword}/msiempy/index.html"
            fi

            echo "[SUCCESS] Documentation on line at : ${url}"

            echo "[BEGIN] PyPI upload"
            rm -rf dist

            echo "[RUNNING] python3 setup.py build check sdist bdist_wheel"
            python3 setup.py build check sdist bdist_wheel
            
            echo '[INFO] Dont forget to run tests with ./setup.py test'
            echo '[INFO] And dont forget to bump __version__'
            echo '[INFO] Hit ctrl+C to cancel PyPI upload'

            if [ "$keyword" = "master" ]; then
                echo "[RUNNING] twine upload --verbose dist/*"
                twine upload --verbose dist/*
                echo "[SUCCESS] Module published at : https://pypi.org/project/msiempy/"
            fi
            if [ "$keyword" = "test" ]; then
                echo "[RUNNING] twine upload --repository-url https://test.pypi.org/legacy/ dist/*"
                twine upload --repository-url https://test.pypi.org/legacy/ dist/*
                echo "[SUCCESS] Module published at : https://test.pypi.org/project/msiempy/"
            fi

            echo "[SUCCESS] Documentation on line at : ${url}"

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