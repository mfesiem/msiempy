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

- Commits to `main` branch are trigerring: 
    - Tests on Windows and MacOS and Ubuntu + upload coverage
    - Generate documentation: 
        If tag release: [publish to gh-pages](https://mfesiem.github.io/docs/msiempy/)
        Else: publish [under `dev` folder](https://mfesiem.github.io/docs/msiempy/dev)
    - Release to PyPI on git tags

See the github actions workflows for more details.  

### Publish

Publishing to PyPI is done via a GitHub Actions workflow that is triggered when a tag is pushed.

First commit the version update to master and wait for tests to pass.

You can push a tab by creating a GitHub Release <https://github.com/mfesiem/msiempy/releases/new>

You can also create a tag on local branch then push it:

    git tag 0.3.5
    git push --tags

The tag name should match extacly the version number. 

### Documentation
Documentation is automatically generated with [`pydoctor`](https://pydoctor.readthedocs.io/en/latest/) from docstrings. 

Format use in docstrings is ReStructuredText.

The script `buid_docs.sh` build documentation.  

For more infos:
```
% ./build_docs.sh -h
```
### Code analysis

[Codacy](https://www.codacy.com/gh/mfesiem/msiempy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=mfesiem/msiempy&amp;utm_campaign=Badge_Grade)

[Code climate](https://codeclimate.com/github/mfesiem/msiempy/maintainability)

### Error report

Configure log file reporting in the configuration file and and look for ``"ERROR"``.  
Useful shell command to get simple list of errors::  

        cat /path/to/your/log/file | grep -i error | sort | uniq
