FROM debian:stretch
LABEL maintainer="Egodcoin Developers <dev@egodcoin.org>"
LABEL description="Dockerised EgodcoinCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
