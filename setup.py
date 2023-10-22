import setuptools


setuptools.setup(
    version="0.0.1",
    license='mit',
    name="py-aws",
    author='nathan todd-stone',
    author_email='me@nathants.com',
    url='http://github.com/nathants/py-aws',
    packages=['aws'],
    install_requires=['boto3',
                      'pytz',
                      'tzlocal',
                      'requests',
                      'awscli',
                      'pager'],
    entry_points={'console_scripts': ['ec2 = aws.ec2:main',
                                      's3 = aws.s3:main',
                                      's3-stubbed = aws.s3_stubbed:main',
                                      'elb = aws.elb:main',
                                      'emr = aws.emr:main',
                                      'ddb = aws.ddb:main']},
    scripts = ['bin/stub_s3.sh'],
    description='aws',
)
