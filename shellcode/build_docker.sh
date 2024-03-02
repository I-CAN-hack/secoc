#!/usr/bin/env bash


docker build -t v850-gcc .
docker run --rm -v $(pwd):/src v850-gcc ./build.sh
