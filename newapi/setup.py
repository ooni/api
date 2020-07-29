#!/usr/bin/python

from setuptools import setup

setup(
    name="ooniapi",
    packages=["ooniapi"],
    include_package_data=True,
    zip_safe=False,
    entry_points={"console_scripts": ["ooniapi = measurements.cli:cli",]},
)
