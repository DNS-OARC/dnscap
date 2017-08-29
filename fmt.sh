#!/bin/sh

clang-format-4.0 \
    -style=file \
    -i \
    src/*.c \
    src/*.h \
    `find plugins -type f -name '*.c'` \
    `find plugins -type f -name '*.h'`
