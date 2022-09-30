"""Setup.py configuration."""
from setuptools import setup, find_packages

setup(
    name='mplog_parser',
    version='1.0',
    packages=find_packages(),
    url='',
    license='MIT',
    author='CERT Intrinsec',
    author_email='cert@intrinsec.com',
    description='Microsoft Protection Logs Parser',
    py_modules=['mplog_parser'],
    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.9',
    entry_points={
        'console_scripts': [
            'mplog_parser = mplog_parser.main:main',
        ],
    }
)
