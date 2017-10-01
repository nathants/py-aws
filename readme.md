## why

the aws ec2 cli is much too verbose for [sane](https://github.com/nathants/bootstraps/blob/master/scripts/spark_cluster.py) [scripting](https://github.com/nathants/bootstraps/blob/master/scripts/cassandra_cluster.sh).

## what

sugar in cli form over the aws ec2 apis. there is also an experimental port for [azure](http://github.com/nathants/py-azure).

with py-aws you can write short, simple scripts to manipulate ec2. by combining new, ls, ssh, scp, push, and rm, you can do basically everything.

take a look at `ec2 -h` for the complete list of commands.

## more what: aka mapreduce the hard way

pmap provides some sugar over ec2, enabling one to do mapreduce the hardway, but without much actual hardness. in the process one gets a lot closer to the metal, which is very helpful when efficiency inevitably becomes a concern.

the general idea is that a cluster of stateless servers run idempotent tasks which read from and write to s3. these tasks can be literally anything. as with typical mapreduce, you will likely construct a dag of jobs, each one feeding the next metadata about locations in s3.

since s3 list operations are never used, and keys are never updated, one can take advantage of s3's read-after-write consistency and sleep well at night.

you can even use [s4](http://github.com/nathants/s4) for intermediate task storage on the cluster, saving a roundtrip when shuffling data, and significantly increasing throughput.

for best results, deploy on ec2's i3.large or i3.xlarge clusters, which balance spot price and throughput well. i3 instances have much faster sustained throughput to s3, lan, and disk than previous instance types. one quickly becomes bottlenecked on cpu and starts rewriting slow tasks in [c](http://github.com/nathants/c-utils).

## tutorial

```
ids=$(ec2 new mapreduce-cluster --type i3.xlarge --spot 1.0 --num 50)
ec2 ssh $ids --yes --command 'sudo apt-get update && ...'
ec2 scp step*.sh :/home/ubuntu/ $ids --yes
tmp=$(ec2 pmap $ids $(cat s3_inputs.txt) 'bash /home/ubuntu/step1.sh')
result=$(ec2 pmap $ids "$tmp" 'bash /home/ubuntu/step2.sh')
echo "$result" | aws s3 cp - s3://.../result.s3_urls
ec2 rm $ids --yes
```

## install:

note: tested only on ubuntu

```
sudo apt-get install python3-pip libyaml-dev
git clone https://github.com/nathants/py-aws
cd py-aws
pip3 install -r requirements.txt
pip3 install .
ec2 -h
```

## configure

requires python3.4 or higher.
aws creds via http://boto3.readthedocs.org/en/latest/guide/configuration.html#environment-variables

requires the following variables:
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_DEFAULT_REGION`


## changing regions:
cli usage:

`region=other-region-1 ec2 ls -s running`

api usage:

```
import aws.ec2
with aws.ec2._region('other-region-1'):
    aws.ec2.ls(state='running')
 ```

## testing with s3

the aws s3 cli is quite good, and can be used to make scripts for [mapreduce](#more-why-aka-map-reduce-the-hard-way). if you want to test these scripts in a more permanent way, there is an entrypoint level stub for the aws cli, which hits local disk instead of s3. it makes programming directly against s3, and sanely testing said programs, much easier. you can also interact with stubbed s3 in a normal terminal session.

it is recommended to use fake bucket names in your s3 urls to protect yourself from accidentally hitting prod from tests.

- example usage
   ```
   #!/bin/bash
   . stub_s3.sh
   py.test tests.py
   bash more_tests.sh
   clear-s3-stubbed
   ```

- interactive session
   ```
   >> . stub_s3.sh

   >> echo foo | aws s3 cp - s3://fake-bucket/path/key.txt

   >> aws s3 cp s3://fake-bucket/path/key.txt -
   foo

   >> clear-s3-stubbed
   $ rm -rf /tmp/s3_stubbed_session_e9ba1197-c3bf-4f38-85ee-680c4b641cb7

   >> aws s3 cp s3://fake-bucket/path/key.txt -
   download failed: s3://fake-bucket/path/key.txt to - An error occurred (403) when calling the HeadObject operation: Forbidden
   ```
