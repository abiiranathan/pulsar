from pathlib import Path
from setuptools import setup, find_packages

# Read long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="pulsar-python",
    version="1.0.1",
    description="Python wrapper for Pulsar web server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Dr. Abiira Nathan",
    author_email="nabiira2by2@gmail.com",
    packages=find_packages(),
    package_dir={"": "."},
    package_data={
        "pulsar": ["lib/*.so", "lib/*.dylib", "lib/*.dll"],
    },
    include_package_data=True,
    python_requires=">=3.8",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
    ],
    keywords="web server http framework",
    url="https://github.com/abiiranathan/pulsar/tree/main/python",
    project_urls={
        "Bug Reports": "https://github.com/abiiranathan/pulsar/issues",
        "Source": "https://github.com/abiiranathan/pulsar/tree/main/python",
    },
)