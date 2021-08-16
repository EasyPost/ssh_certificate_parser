#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name="ssh_certificate_parser",
    version="1.3.1",
    author="James Brown",
    author_email="jbrown@easypost.com",
    url="https://github.com/easypost/ssh_certificate_parser",
    license="ISC",
    packages=find_packages(exclude=['tests']),
    description="Python library for interacting with OpenSSH Certificates",
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    install_requires=[
        'attrs>=16',
    ],
    project_urls={
        'Docs': 'https://readthedocs.org/projects/ssh-certificate-parser/',
        'Tracker': 'https://github.com/EasyPost/ssh-certificate-parser/issues',
        'Source': 'https://github.com/EasyPost/ssh-certificate-parser',
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: ISC License (ISCL)",
    ]
)
