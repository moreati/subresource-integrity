from setuptools import setup

import io
import os


def read(fname, encoding='utf-8'):
    path = os.path.join(os.path.dirname(__file__), fname)
    with io.open(path, encoding=encoding) as f:
        return f.read()

setup(
    name='subresource-integrity',
    version=0.2,
    license='BSD',
    description='Create and parse HTML subresource integrity values',
    long_description=read('README.rst'),

    author='Alex Willmer',
    author_email = 'alex@moreati.org.uk',
    url='https://github.com/moreati/subresource-integrity',

    py_modules=['subresource_integrity'],

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)

