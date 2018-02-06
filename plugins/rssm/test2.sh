#!/bin/sh -xe

"$srcdir"/dnscap-rssm-rssac002 --sort "$srcdir/test1.gold" "$srcdir/test1.gold" "$srcdir/test1.gold" > test2.out

diff test2.out "$srcdir/test2.gold"
