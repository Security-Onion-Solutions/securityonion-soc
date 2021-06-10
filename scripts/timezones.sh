#!/bin/sh

cd /usr/share/zoneinfo
find -type f | cut -c 3- | sort | grep -v ".tab\|tzdata\|right\/\|SystemV\/\|posix\/\|localtime\|Factory\|seconds\|posixrules"