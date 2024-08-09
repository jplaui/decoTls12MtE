# deco-oracle
### Clone repo
Clone repos:
```
    $ git clone git@github.com:januspaper/deco12mte-reimplementation.git
    $ git checkout handshake
```
### Docker setup
Create a Docker image. You only have to do this
once.
```
$ docker build -t deco .
```
Spin up a Docker container from the image.
```
$ docker run -it deco
```
Please note that any changes you make in the container are not persistent.

## Run application 
Execute the same docker container in another two seperate consoles.
```
$ docker exec -it CONTAINERID /bin/bash 
```
Change directory to app folder.
```
$ cd ~/deco-oracle/app
```
Change to the corresponding directory
```
$ cd ~/deco-oracle/app/server
```
Always run server(verifier) first
```
$ go run ./server.go 
```
Then run verifier(server)
```
$ go run ./verifier.go
```
Run client at last
```
$ go run ./client.go
```

## MPC resources:

We need to implement the following components in MPC:

- ADD Gate
- PRF SHA-256 Gate for (i) master secret (ii) key derivation
- Two XOR Gates

Tricky part: How to design the SHA-256 Gate without extensive effort?

- Bristol Fashion MPC circuit for SHA256 can be found [here](https://homes.esat.kuleuven.be/~nsmart/MPC/).
- The circuit was created in VHDL as specified in SCALE MAMBA [here](https://github.com/KULeuven-COSIC/SCALE-MAMBA/tree/master/Circuits/VHDL/SHA256)
- SCALE MAMBA has an extremely good documentation, see [here](https://homes.esat.kuleuven.be/~nsmart/SCALE/Documentation-SCALE.pdf)
- Another implementation is described in [this](https://dl.acm.org/doi/pdf/10.1145/3133956.3134060) paper, however I did not yet find the circuit file for their implementation. 
- It  probably makes the most sense to base the MPC imlementation on the [EMP toolkit](https://github.com/MPC-SoK/frameworks/tree/master/emp), as it provides an extensive framework. However, their documentation is a bit sparse.
- The ABY toolkit is very neat, however we would not be able to use the SHA256 circuit, as they use a circuit description that is slightly different to the Bristol fashion. The documentation is very good to get a general understanding, I recommend taking a look [here](https://www.informatik.tu-darmstadt.de/media/encrypto/encrypto_code/abydevguide.pdf).

Malicious MPC:

- With semi-honest MPC we run into a problem - the party who constructs the garbled circuit could just cheat. In order to prevent such behavior, we have the party construct many copies of the circuit and then ask it to open half of them
- Not very efficient BUT much more secure than semi-honest.
- DECO protocol is based on [this](https://eprint.iacr.org/2017/030.pdf) paper.

