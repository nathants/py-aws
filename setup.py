import setuptools


setuptools.setup(
    version="0.0.1",
    license='mit',
    name="py-aws",
    author='nathan todd-stone',
    author_email='me@nathants.com',
    url='http://github.com/nathants/py-aws',
    packages=['aws'],
    install_requires=['boto3 >1, <2',
                      'pager >3, <4',
                      'awscli >1, <2'],
    entry_points={'console_scripts': ['ec2 = aws.ec2:main',
                                      'elb = aws.elb:main',
                                      'launch = aws.launch:main']},
    description='aws',
)
