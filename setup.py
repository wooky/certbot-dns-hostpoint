from setuptools import setup
from setuptools import find_packages

version = "0.1.0"

install_requires = [
    "acme>=0.29.0",
    "certbot>=0.34.0",
    "setuptools",
    "requests",
#    "mock",
#    "requests-mock",
]

# # read the contents of your README file
# from os import path

# this_directory = path.abspath(path.dirname(__file__))
# with open(path.join(this_directory, "README.rst")) as f:
#     long_description = f.read()
long_description = "TODO"

setup(
    name="certbot-dns-hostpoint",
    version=version,
    description="Hostpoint DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/wooky/certbot-dns-hostpoint",
    author="Yakov Lipkovich",
    author_email="github@yakov.ca",
    license="Apache License 2.0",
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        "certbot.plugins": [
            "dns-hostpoint = certbot_dns_hostpoint.dns_hostpoint:Authenticator"
        ]
    },
    # test_suite="certbot_dns_hostpoint",
)
