#!/usr/bin/env python3

import setuptools
from distutils.core import setup

setup(name='rawcat',
      version='1.0',
      description='Raw socket comms',
      author='Paul Jordan',
      author_email='paullj1@gmail.com',
      packages=['rawcat'],
      install_requires=[
          'scapy'
      ],
      entry_points = {
          'console_scripts': [
              'rawcat=rawcat.rawcat:main',
          ],
      })



