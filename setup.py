#! /usr/bin/env python3

from setuptools import setup
import pathlib


# The directory containing this file
HERE = pathlib.Path(__file__).parent

#Version of the project
version = {}
exec((HERE / "msiempy" / "__version__.py").read_text(), version)

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name='msiempy',
    description="McAfee SIEM API Python wrapper",
    url='https://github.com/mfesiem/msiempy',
    maintainer='andywalden, tristanlatr, mathieubeland',
    maintainer_email='aw@krakencodes.com, tris.la.tr@gmail.com',
    version=version['__version__'],
    packages=['msiempy',],
    entry_points = {
        'console_scripts': ['msiempy=msiempy.cli:main'],
    },
    install_requires=[
          'requests','tqdm','PTable','python-dateutil', 'urllib3'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    license='The MIT License',
    long_description=README,
    long_description_content_type="text/markdown",
    test_suite="tests"
)