from setuptools import setup
import rcdss

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name=rcdss.__name__,
    version=rcdss.__version__,
    description=rcdss.__doc__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ripe-ncc/rcdss",
    author="Ondřej Caletka",
    author_email="ondrej.caletka@ripe.net",
    packages=["rcdss"],
    setup_requires=["pytest-runner"],
    python_requires=">=3.6",
    install_requires=["dnspython", "cryptography", "click"],
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "rcdss = rcdss.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Systems Administration",
    ],
)
