# AWS SigV4 Auth Cassandra Python Driver 4.x Plugin
# %%
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# %%
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pathlib

from setuptools import setup, find_packages

# Get the long description from the README file
long_description = (pathlib.Path(__file__).parent.resolve() / 'README.md').read_text(encoding='utf-8')

setup(
    name='cassandra-sigv4',
    version='4.0.2',
    description='Implements a sigv4 authentication plugin for the open-source Datastax Python Driver for Apache Cassandra',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/aws/aws-sigv4-auth-cassandra-python-driver-plugin/',
    author='AWS',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    keywords='cassandra,cql,aws,sigv4,authentication,auth',
    packages=find_packages(exclude=["tests"]),
    python_requires='>=2.7, <4',
    install_requires=['cassandra-driver', 'boto3', 'six'],
    tests_require=["mock"],
    test_suite='tests',
    project_urls={
        'Bug Reports': 'https://github.com/aws/aws-sigv4-auth-cassandra-python-driver-plugin/issues',
        'Source': 'https://github.com/aws/aws-sigv4-auth-cassandra-python-driver-plugin/',
    },
)
