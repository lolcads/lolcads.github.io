#!/usr/bin/env bash

if [[ $# -ne 1 ]]
then
    echo "usage: $0 <filename> (e.g. test -> will create a test.md file)"
    exit 1
fi

year=$(date '+%Y')
month=$(date '+%m')
hugo new posts/"${year}/${month}/${1}.md"

static_images_path="static/${year}/${month}"

if [[ ! -e  $static_images_path ]]
then
    mkdir -p $static_images_path
    touch $static_images_path/.gitkeep
    echo "info: created ${static_images_path} for images"
else
    echo "info: you can use ${static_images_path} for images"
fi
