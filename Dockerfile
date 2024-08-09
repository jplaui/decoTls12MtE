FROM --platform=linux/amd64 ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y wget git gcc

RUN wget -P /tmp https://dl.google.com/go/go1.17.7.linux-amd64.tar.gz

RUN tar -C /usr/local -xzf /tmp/go1.17.7.linux-amd64.tar.gz
RUN rm /tmp/go1.17.7.linux-amd64.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

WORKDIR /root
RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  git \
  libssl-dev \
  sudo \
  wget \
  python3 \
  vim \
  libgmp3-dev \
  libprocps-dev \
  python3-markdown \
  libssl-dev \
  openjdk-17-jdk \
  junit4 \
  python3-markdown\
  libboost-program-options-dev \
  pkg-config
RUN mkdir -p ./deco-oracle
ADD jsnark/ ./deco-oracle/jsnark
ADD 2pc/ ./deco-oracle/2pc
ADD app/ ./deco-oracle/app
ADD src/ ./deco-oracle/src
ADD README.md ./deco-oracle/
ADD install.sh .
ADD config.yml ./deco-oracle

RUN ["/bin/bash", "install.sh"]
CMD ["/bin/bash"]
