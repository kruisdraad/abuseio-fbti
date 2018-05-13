#!/bin/bash
pwd=`pwd`
basename=`basename $pwd`

if [ "$basename" == "failed_objects" ]; then
  for file in `find ./ | grep json`; do (php ../../artisan job:retry $file --delete &); done
  find ./ -type d -empty -delete
else
  echo "enter failed_object dir first!"
fi

