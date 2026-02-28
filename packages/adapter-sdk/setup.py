from setuptools import setup, find_packages

setup(
    name="m87-adapter-sdk",
    version="0.1.0",
    description="SDK for building M87 agent adapters",
    author="M87 Studio LLC",
    license="BSL-1.1",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pydantic>=2.0.0",
        "httpx>=0.24.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
)
