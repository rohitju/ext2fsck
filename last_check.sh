#!/bin/bash
# Usage:
#     ./last_check.sh <absolute_path_of_disk_image>
#
# This script checks whether your fsck project submission meets the grading requirement
# It takes only one arguement: the absolute path of the disk image file

if [ $# -ne 1 ] 
then
    echo "Invalid argument count"
    echo "Usage: ./last_check.sh <absolute_path_of_disk_image>"
    exit
fi

disk=$1

reportError()
{
    if [ $? -ne 0 ] 
    then
	rm -rf ../foo
        echo $1
	exit
    fi
}

mkdir foo; cd foo

tar xf ../myfsck.tar
reportError "FAIL: Cannot extract tar ball!"

make
reportError "FAIL: Cannot make!"

./myfsck -p 1 -i $disk
reportError "FAIL: Cannot print partition table!"

./myfsck -f 0 -i $disk
reportError "FAIL: Cannot correct errors on disk image!"

rm -rf ../foo
echo "SUCCESS! You are ready to submit your code!"
