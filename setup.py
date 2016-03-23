import setuptools


setuptools.setup(
    version="0.0.1",
    license='mit',
    name="py-aws",
    author='nathan todd-stone',
    author_email='me@nathants.com',
    url='http://github.com/nathants/py-aws',
    packages=['aws'],
    install_requires=['boto3==1.2.6',
                      'pager==3.3',
                      'awscli==1.10.14'],
    entry_points={'console_scripts': ['ec2 = aws.ec2:main',
                                      'launch = aws.launch:main']},
    description='aws',
)
