#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='richheader',
    version='0.2',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/RichHeader',
    description='Rich Header parser.',
    long_description=open('README.md').read(),
    packages=['richheader'],
    scripts=['bin/RichHeaderCLI.py'],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ],
)
