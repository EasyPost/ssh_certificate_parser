#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name="ssh_certificate_parser",
    version="1.2.0",
    author="James Brown",
    author_email="jbrown@easypost.com",
    url="https://github.com/easypost/ssh_certificate_parser",
    license="ISC",
    packages=find_packages(exclude=['tests']),
    description="Python library for interacting with OpenSSH Certificates",
    long_description=open('README.md', 'r').read(),
    install_requires=[
        'attrs>=16',
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Operating System :: POSIX",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: ISC License (ISCL)",
    ]
)
