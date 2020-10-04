### Questions ?  

If you have any questions, please create a new issue.  

### Contribute  

If you like the project and think you could help with making it better, there are many ways you can do it:   

- Create new issue for new feature proposal or a bug
- Implement existing issues
- Help with improving the documentation
- Spread a word about the project to your collegues, friends, blogs or any other channels
- Any other things you could imagine
- Any contribution would be of great help and I will highly appreciate it!

### Install for dev
```
For development
# Fork the repo
git clone https://github.com/mfesiem/msiempy.git
cd msiempy
# Install dev requirements
python3 -m pip install -r requirements.txt
# Install module
python3 ./setup.py install
# Hack and pull request
```

### Git flow
- Commits to `master` branch are trigerring: 
    - Tests + upload coverage
    - Generate documentation + publish to gh-pages
    - PyPi realeases and create new tag **if the `__version__` has been bumped**.  
    - See [publish](https://github.com/mfesiem/msiempy/blob/master/.github/workflows/publish.yml)
- Commits to `develop` branch are trigerring:
    - Generate documentation + publish to gh-pages under `test` folder
    - See [publish-test-docs-only](https://github.com/mfesiem/msiempy/blob/master/.github/workflows/publish-test-docs-only.yml)
- Tests on Windows and MacOS are scheduled to run once a week. 
    - See [test](https://github.com/mfesiem/msiempy/blob/master/.github/workflows/test.yml)

See the github actions workflows for more details: 