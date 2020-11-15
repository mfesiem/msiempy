#! /usr/bin/env python3

from setuptools import setup, find_packages
import pathlib

# REQUIREMENTS
REQUIREMENTS = [ 'requests', 'tqdm', 'PTable', 'python-dateutil', 'urllib3' ]

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# About the project
about = {}
exec((HERE / "msiempy" / "__version__.py").read_text(), about)

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name=about['__title__'],
    description=about['__description__'],
    url=about['__url__'],
    maintainer=about['__author__'],
    maintainer_email=about['__author_email__'],
    version=about['__version__'],
    packages=find_packages(exclude='tests',),
    install_requires=REQUIREMENTS,
    license=about['__license__'],
    long_description=README,
    long_description_content_type="text/markdown",
    test_suite="tests",
    keywords=about['__keywords__'],
    classifiers=[
        "Programming Language :: Python :: 3",
        'Intended Audience :: Developers',
        'Development Status :: 4 - Beta',
    ],
)