#!/usr/bin/env python

import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


from distutils import sysconfig


LIB_PATH = sysconfig.get_python_lib()
TWISTED_PLUGINS = os.path.join(LIB_PATH, 'twisted', 'plugins')


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='esmed',
    version='0.1.1',
    description='SMPP ESME daemon (esmed)',
    long_description=read('README.rst'),
    author='Alexander Pravdin',
    author_email='aledin@mail.ru',
    url='https://github.com/xanderdin/esmed',
    license='Apache License 2.0',
    install_requires=[
        'twisted',
        'psycopg2',
        'txpostgres',
        'ptsmpp',
    ],
    package_dir={
        '': 'src'
    },
    packages=[
        'esmed',
    ],
    data_files=[
        # Twisted plugin
        # '.pyc' extension is necessary for correct plugins removing
        (TWISTED_PLUGINS, ['src/twisted/plugins/esmed_plugin.py', 'setup/esmed_plugin.pyc',]),
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Twisted",
        "Environment :: No Input/Output (Daemon)",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Topic :: System :: Networking",
    ],
)