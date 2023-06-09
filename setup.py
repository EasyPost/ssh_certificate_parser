#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="ssh_certificate_parser",
    version="1.6.0",
    author="James Brown",
    author_email="jbrown@easypost.com",
    url="https://github.com/easypost/ssh_certificate_parser",
    license="ISC",
    packages=find_packages(exclude=["tests"]),
    description="Python library for interacting with OpenSSH Certificates",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    install_requires=[
        "attrs>=16",
    ],
    project_urls={
        "Docs": "https://ssh-certificate-parser.readthedocs.io/",
        "Tracker": "https://github.com/EasyPost/ssh_certificate_parser/issues",
        "Source": "https://github.com/EasyPost/ssh_certificate_parser",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: ISC License (ISCL)",
    ],
)
