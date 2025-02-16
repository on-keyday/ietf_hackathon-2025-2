#!/bin/bash

go generate ./...


# create temporary builder
if ! CREATED_BUILDER=$(docker buildx create --driver docker-container)
then
    echo "Failed to create builder"
    exit 1
fi

# use builder
TARGET_PATH=./frr-compose.yaml

# build docker image
if ! docker buildx bake\
        -f $TARGET_PATH\
        --builder "$CREATED_BUILDER"\
        --load \
        --progress=plain \
        --set "*.cache-from=type=local,src=$(pwd)/.buildx-cache"\
        --set "*.cache-to=type=local,dest=$(pwd)/.buildx-cache"
then
    docker buildx rm "$CREATED_BUILDER"
    echo "Failed to build image"
    exit 1
fi

# remove builder
docker buildx rm "$CREATED_BUILDER" 

docker compose -f $TARGET_PATH create --remove-orphans --force-recreate
docker compose -f $TARGET_PATH start

docker compose logs -f