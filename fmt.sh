#!/bin/sh

clang-format \
    -style=file \
    -i \
    src/*.c \
    src/*.h \
    `find plugins -type f -name '*.c'` \
    `find plugins -type f -name '*.h'`
