import os
from setuptools import setup, find_packages
import aioradius

def read_file(f):
    return open(os.path.join(os.path.dirname(__file__), f)).read().strip()


def read_version():
    if 'AIORADIUS_VERSION' in os.environ:
        return os.environ['AIORADIUS_VERSION']
    else:
        return aioradius.__version__

classifiers = [
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Intended Audience :: Developers',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Operating System :: POSIX :: Linux',
    'Environment :: Other Environment',
    'Development Status :: 2 - Pre-Alpha',
    'Topic :: Internet',
    'Framework :: AsyncIO',
]


setup(
    name="aioradius",
    include_package_data = True,
    version=read_version(),
    description=('AsyncIO implementation of RADIUS protocol for server and client'),
    long_description=read_file('README.md'),
    classifiers=classifiers,
    platforms=['POSIX'],
    author="Alexey Rusivon",
    author_email="cyberalex.ru@gmail.com",
    packages=find_packages(),
    test_suite="tests",
    install_requires=[
        'ipaddress',
        'six',
        'bidict',
        'expiringdict'
    ]
)
