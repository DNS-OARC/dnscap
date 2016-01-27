## Simple dirty script for compiling dnscap with
## SECCOMP-BPF and some compiler hardening flags

gcc -Wall -g -O2  -c dnscap.c -DSECCOMP=1
gcc -Wall -g -O2  -c dump_dns.c -DSECCOMP=1
gcc -o dnscap  dnscap.o dump_dns.o  -ldl -lpcap -lresolv -lseccomp -fPIE -fstack-protector-all -Wl,-z,relro -Wformat -Wformat-security -Werror=format-security -D_FORTIFY_SOURCE=2
