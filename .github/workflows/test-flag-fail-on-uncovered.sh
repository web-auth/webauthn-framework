#!/bin/sh

vendor/bin/deptrac analyse --fail-on-uncovered --no-cache

if [ $? -ne 1 ]; then
  exit 1;
fi
