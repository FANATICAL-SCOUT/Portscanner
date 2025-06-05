from setuptools import setup, find_packages

setup(
    name="port-scanner",  # Package name on PyPI
    version="1.0.0",
    description="Advanced Network Scanner with Port Scanning, MAC Spoofing and Vulnerability Detection",
    author="Your Name",
    author_email="your.email@example.com",  # Add your email
    url="https://github.com/yourusername/port-scanner",  # Add your GitHub URL
    py_modules=["pscan", "scanner", "vuln_scanner", "mac_spoofer", "decoy_scanner"],
    entry_points={
        'console_scripts': [
            'pscan=pscan:main',  # Creates the command
        ],
    },
    install_requires=[
        'requests',
        'scapy',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.6",
)