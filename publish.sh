#!/bin/bash
#Setting bash strict mode. See http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail
IFS=$'\n\t,'

usage(){
    echo "[USAGE] $0 [-h] [-p] <test/master>" 1>&2
    echo
    echo "Help us publish msiempy on the internet."
    echo
    echo -e "\t-h\tPrint this help message."
    echo -e "\t-p\t<test/master>\tGit tag, push the technical documentation and publish to PyPi. In this order."
    echo
    echo -e "\t\t'test' keyword : "
    echo -e "\t\t\t- Tag version with '-test' flag"
    echo -e "\t\t\t- Publish docs to https://mfesiem.github.io/docs/test/msiempy/"
    echo -e "\t\t\t- Publish module to https://test.pypi.org/project/msiempy/"
    echo
    echo -e "\t\t'master' keyword : "
    echo -e "\t\t\t- Delete '-test' tag and tag version"
    echo -e "\t\t\t- Publish docs to https://mfesiem.github.io/docs/msiempy/"
    echo -e "\t\t\t- Publish module to https://pypi.org/project/msiempy/"
    echo
    exit -1
}

while getopts ":hp:" arg; do
    case "${arg}" in
        h) #Print help
            usage
            ;;

        p)
            # Figuring version
            version=`grep __version__ ./msiempy/__version__.py | cut -d "'" -f 2`
        
            # Checking keyword
            keyword=${OPTARG}

            if [ "$keyword" = "master" ]; then
                docs_folder="mfesiem.github.io/docs"
                repository_url="https://pypi.org"
                # Deleting '-test' tag  if it exists
                if [ -n `git tag -l "${version}-test"` ]; then
                    echo "[RUNNING] git tag -d ${version}-test && git push origin --delete ${version}-test"
                    git tag -d ${version}-test && git push origin --delete ${version}-test
                fi

                # Tag
                echo "[RUNNING] git tag -a ${version} -m "Version ${version}" && git push --tags"
                git tag -a ${version} -m "Version ${version}" && git push --tags

            else
                if [ "$keyword" = "test" ]; then
                    docs_folder="mfesiem.github.io/docs/test"
                    repository_url="https://test.pypi.org"

                    read -p "[QUESTION] Do you want to tag this version with a '-test' flag? [y/n]" -n 1 -r
                    echo    # (optional) move to a new line
                    if [[ $REPLY =~ ^[Yy]$ ]]
                    then
                        # Deleting '-test' tag if it exists
                        if [ -n `git tag -l "${version}-test"` ]; then
                            echo "[RUNNING] git tag -d ${version}-test && git push origin --delete ${version}-test"
                            git tag -d ${version}-test && git push origin --delete ${version}-test
                        fi
                        # Test tag
                        echo "[RUNNING] git tag -a ${version}-test -m "Version ${version}-test" && git push --tags"
                        git tag -a ${version}-test -m "Version ${version}-test" && git push --tags
                    fi
                    
                
                else
                    echo "[ERROR] The keyword must be 'test' or 'master'"
                    exit -1
                fi
            fi

            # Generating diagrams
            echo "[RUNNING] pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy"
            pyreverse -s 1 -f PUB_ONLY -o png -m y msiempy

            # Cloning or pulling changes from the documentation
            if [[ ! -d mfesiem.github.io ]]; then
                echo "[RUNNING] git clone https://github.com/mfesiem/mfesiem.github.io"
                git clone https://github.com/mfesiem/mfesiem.github.io
            else
                echo "[RUNNING] cd mfesiem.github.io && git pull -v && cd .."
                cd mfesiem.github.io && git pull --quiet && cd ..
            fi
            
            # Generating documentation
            echo "[RUNNING] pdoc3 msiempy --output-dir ./mfesiem.github.io/docs --html --force"
            rm -rf ./${docs_folder}/msiempy/
            pdoc3 msiempy --output-dir ./${docs_folder} --html --force
            mv ./classes.png ./${docs_folder}/msiempy
            mv ./packages.png ./${docs_folder}/msiempy
            
            # Pushing docs
            echo "[RUNNING] cd mfesiem.github.io && git add . && git commit -m \"Generate ${keyword} docs $(date)\" && git push origin master"
            cd mfesiem.github.io && git add . && git commit -m "Generate ${keyword} docs $(date)" --quiet && git push origin master --quiet
            cd ..
            
            echo "[SUCCESS] Documentation at : https://${docs_folder}/msiempy/"

            # Building module
            echo "[RUNNING] python3 setup.py build check sdist bdist_wheel"
            rm -rf dist
            python3 setup.py --quiet build check sdist bdist_wheel
            
            # Publish to PyPi
            echo "[RUNNING] twine upload dist/*"
            if [ "$keyword" = "master" ]; then
                twine upload dist/*
            else
                twine upload --repository-url ${repository_url}/legacy/ dist/*
            fi
            python3 setup.py --quiet clean

            echo "[SUCCESS] Module published at : https://${repository_url}/project/msiempy/"
            ;;

        *)
            echo "[ERROR] Syntax mistake calling the script."
            usage
            exit
            ;;
    esac
done
shift $((OPTIND-1))
echo "[END] usage: $0 [-h] [-p <test/master>]"