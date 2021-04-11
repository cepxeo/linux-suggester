#! /bin/bash -x
host=YOUR_IP
user=username
key=id_rsa
scp -i $key linux-suggester.py $user@$host:/tmp/
ssh -i $key $user@$host "chmod +x /tmp/linux-suggester.py && python /tmp/linux-suggester.py > /tmp/linux-suggester.log
mkdir log
scp -i $key $user@$host:/tmp/linux-*.log log/
ssh -i $key $user@$host "rm /tmp/linux-*"
