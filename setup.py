from setuptools import setup, find_packages

setup(
    name='p4pktgen',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    entry_points={'console_scripts': [
        'p4pktgen = p4pktgen.main:main',
    ]})
