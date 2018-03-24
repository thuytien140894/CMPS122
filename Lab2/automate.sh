#!/bin/bash

# check for the number of arguments
# https://stackoverflow.com/a/4341647/7542147
if [ "$#" -ne 4 ]; then
  echo "Usage: $0 [ipaddress] $1 [skeleton key] $2 [username] $3 [dictionary] $4" 
  exit 1
fi

cd src/
make clean
make

./findbackdoor $1 $2 $3 $4
 
chmod 777 binary
mv binary ./..
mv source.c ./..

cd ..

echo BINARY
file binary
echo -------------------------------------------------------------------------------------------------------------------
echo SOURCE
cat source.c
echo ------------------------------------------------------------------------------------------------------------------- 
python python/smash_input.py

mv in.txt ./src/

cd src/
./smash serverinfo.txt





