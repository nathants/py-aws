requires python3.4 or higher.
aws creds via http://boto3.readthedocs.org/en/latest/guide/configuration.html#environment-variables

requires the following variables:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_DEFAULT_REGION`

install:

`sudo apt-get install python3-pip libyaml-dev`

`git clone https://github.com/nathants/py-aws`

`cd py-aws`

`pip3 install -r requirements.txt`

`pip3 install .`

`ec2 -h`

changing regions:
 - cli usage:

 `region=other-region-1 ec2 ls -s running`

 - api usage:

 ```
 import aws.ec2
 with aws.ec2._region('other-region-1'):
     aws.ec2.ls(state='running')
 ```
