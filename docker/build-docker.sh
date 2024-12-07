#!/usr/bin/env bash

export LC_ALL=C

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/.. || exit

DOCKER_IMAGE=${DOCKER_IMAGE:-Egodcoin/egodcoind-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/egodcoind docker/bin/
cp $BUILD_DIR/src/egodcoin-cli docker/bin/
cp $BUILD_DIR/src/egodcoin-tx docker/bin/
strip docker/bin/egodcoind
strip docker/bin/egodcoin-cli
strip docker/bin/egodcoin-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
