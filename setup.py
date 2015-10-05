import setuptools
import os


setuptools.setup(
    version="0.0.1",
    license='mit',
    name="py-aws",
    author='nathan todd-stone',
    author_email='me@nathants.com',
    url='http://github.com/nathants/py-aws',
    packages=setuptools.find_packages(),
    install_requires=open('requirements.txt').readlines(),
    entry_points={'console_scripts': [
        '{} = aws.{}:main'.format(
            x.replace('.py', '').replace('_', '-'),
            x.replace('.py', '')
        )
        for x in os.listdir('aws')
        if not x.startswith('_')
        and not x.startswith('.')
        and not x.endswith('.pyc')
    ]},
    description='aws',
)
