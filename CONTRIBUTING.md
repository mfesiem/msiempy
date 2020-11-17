### Questions ?  

If you have any questions, please create a new issue.  

### Contribute  

If you like the project and think you could help with making it better, there are many ways you can do it:   

- Create new issue for new feature proposal or a bug
- Implement existing issues.
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

### Run Tests


All tests are not compatible with any ESM instance. But all tests will be run once merged with `develop` branch

You might want to run per-file tests
```
pytest tests/auth/test_device.py
```

Or per-method test
```
python3 -m unittest tests.auth.test_event.T.test_add_note
```


### Git flow
- Commits to `master` branch are trigerring: 
    - Tests on Windows and MacOS and Ubuntu + upload coverage
    - Generate documentation + publish to gh-pages
    - PyPi realeases and create new tag **if the `__version__` has been bumped**.  

- Commits to `develop` branch are trigerring:
    - Generate documentation + publish to gh-pages under `test` folder


See the github actions workflows for more details.  

### Documentation
Documentation is automatically generated with `pydoctor` from docstrings. 

The main documentation is in the `msiempy/__init__.py` file.  

Format use in docstrings is ReStructuredText.