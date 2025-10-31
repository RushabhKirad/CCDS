from setuptools import setup, find_packages

setup(
    name="email-security-system",
    version="1.0.0",
    description="AI-powered Gmail email security system with phishing detection",
    author="Rushabh Kirad",
    author_email="rushabhkirad@gmail.com",
    packages=find_packages(),
    install_requires=[
        "Flask==2.3.3",
        "mysql-connector-python==8.1.0",
        "scikit-learn==1.3.0",
        "numpy==1.24.3",
        "pandas==1.5.3",
        "joblib==1.3.2",
        "imaplib2==3.6",
        "cryptography==41.0.4",
        "psutil==5.9.5",
        "python-dotenv==1.0.0"
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)