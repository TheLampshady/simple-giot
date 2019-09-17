import io
import os

import setuptools


name = "simple-giot"
description = "A simple Google IoT Core Device base class."
version = "0.1.0"
# Should be one of:
# 'Development Status :: 3 - Alpha'
# 'Development Status :: 4 - Beta'
# 'Development Status :: 5 - Production/Stable'
release_status = "Development Status :: 3 - Alpha"
dependencies = [
    "cryptography~=2.7",
    "pyjwt~=1.7",
    "paho-mqtt~=1.4",
]
extras = {}

# Setup boilerplate below this line.

package_root = os.path.abspath(os.path.dirname(__file__))

readme_filename = os.path.join(package_root, "README.md")
with io.open(readme_filename, encoding="utf-8") as readme_file:
    readme = readme_file.read()

# Only include packages under the 'google' namespace. Do not include tests,
# benchmarks, etc.
packages = [
    package for package in setuptools.find_packages() if package.startswith("iot_core_device")
]

setuptools.setup(
    name=name,
    version=version,
    description=description,
    long_description=readme,
    author="Zach Goldstein",
    author_email="zgoldstein@hugeinc.com",
    license="Apache 2.0",
    url="TBD",
    classifiers=[
        release_status,
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Operating System :: OS Independent",
        "Topic :: Internet",
    ],
    platforms="Posix; MacOS X; Windows",
    packages=packages,
    install_requires=dependencies,
    extras_require=extras,
    python_requires=">=3.5",
    include_package_data=True,
    zip_safe=False,
)
