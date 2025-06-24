import platform
from pathlib import Path
from setuptools import setup, find_packages

# Platform detection
SYSTEM = platform.system()
MACHINE = platform.machine()

# Read long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="pulsar-python",
    version="1.0.0",
    description="Python wrapper for Pulsar web server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Dr. Abiira Nathan",
    author_email="nabiira2by2@gmail.com",
    packages=find_packages(where="python"),
    py_modules=["pulsar"],
    package_dir={"": "pulsar"},
    package_data={
        "pulsar": ["lib/*.so", "lib/*.dylib"],
    },
    include_package_data=True,
    python_requires=">=3.8",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
    ],
)
