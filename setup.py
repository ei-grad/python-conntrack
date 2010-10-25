#!/usr/bin/env python

from distutils.core import setup

setup(name='Conntrack',
    version='0.5',
    description='A simple python interface to libnetfilter_conntrack using ctypes.',
    author='Andrew Grigorev',
    author_email='andrew@ei-grad.ru',
    url='http://github.com/ei-grad/python-conntrack',
    py_modules=['Conntrack'],

    classifiers=(
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: System :: Networking :: Monitoring',
        ),

    license="MIT"
)
