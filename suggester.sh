#! /bin/bash -x
#Example: ./suggester.sh host_ip username ssh_key

host=$1
user=$2
key=$3
scp -i $key linux-suggester.py $user@$host:/tmp/
ssh -i $key $user@$host "chmod +x /tmp/linux-suggester.py && python /tmp/linux-suggester.py" > /tmp/linux-suggester.log
mkdir log
scp -i $key $user@$host:/tmp/linux-*.log log/
ssh -i $key $user@$host "rm /tmp/linux-*"
