#!/bin/bash

wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python3 install.py --install --tool --ot --sh2pc --ag2pc
cd ~/deco-oracle/2pc/sh_test
mkdir build && cd build && cmake .. && make
cd ~/deco-oracle/ && mkdir -p ~/deco-oracle/zksnark/bin/c++/2pc/
cp ~/deco-oracle/2pc/sh_test/build/bin/prf ~/deco-oracle/zksnark/bin/c++/2pc/
cp ~/deco-oracle/2pc/sh_test/build/bin/prf_client_finished ~/deco-oracle/zksnark/bin/c++/2pc/
cp ~/deco-oracle/2pc/sh_test/build/bin/prf_server_finished ~/deco-oracle/zksnark/bin/c++/2pc/
cp ~/deco-oracle/2pc/sh_test/build/bin/hmac_setup ~/deco-oracle/zksnark/bin/c++/2pc/
cp ~/deco-oracle/2pc/sh_test/build/bin/hmac_outer_hash ~/deco-oracle/zksnark/bin/c++/2pc/

cd ~/deco-oracle/jsnark/JsnarkCircuitBuilder && wget https://www.bouncycastle.org/download/bcprov-jdk15on-159.jar
cd ~/deco-oracle/jsnark/libsnark/ && mkdir build && cd build && cmake .. -DMULTICORE=ON && make
cd ~/deco-oracle/
cp -r ~/deco-oracle/jsnark/libsnark/build/libsnark/jsnark_interface ~/deco-oracle/zksnark/bin/c++
cd ~/deco-oracle/jsnark/JsnarkCircuitBuilder && mkdir -p bin
javac -d bin -cp /usr/share/java/junit4.jar:bcprov-jdk15on-159.jar  $(find ./src/* | grep ".java$")
cp -r ~/deco-oracle/jsnark/JsnarkCircuitBuilder/bin ~/deco-oracle/zksnark/
cp ~/deco-oracle/jsnark/JsnarkCircuitBuilder/config.properties ~/deco-oracle/zksnark/

