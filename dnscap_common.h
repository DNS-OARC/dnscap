/*
 * setup MY_BPFTIMEVAL as the timeval structure that bpf packets
 * will be assoicated with packets from libpcap
 */
#ifdef __OpenBSD__
# define MY_BPFTIMEVAL bpf_timeval
#endif
#ifndef MY_BPFTIMEVAL
# define MY_BPFTIMEVAL timeval
#endif
typedef struct MY_BPFTIMEVAL my_bpftimeval;


/*
 * Structure to contain IP addresses
 */
typedef struct {
        int                     af;
        union {
                struct in_addr          a4;
                struct in6_addr         a6;
        } u;
} iaddr;

/*
 * plugins can call the logerr() function in the main dnscap
 * process.
 */
typedef int logerr_t(const char *fmt, ...);

/*
 * Prototype for the plugin "output" function
 */
typedef void output_t(const char *descr,
        iaddr from,
        iaddr to,
        uint8_t proto,
        int isfrag,
        unsigned sport,
        unsigned dport,
        my_bpftimeval ts,
        const u_char *pkt_copy,
        unsigned olen,
        const u_char *dnspkt,
        unsigned dnslen);

#define DIR_INITIATE	0x0001
#define DIR_RESPONSE	0x0002
