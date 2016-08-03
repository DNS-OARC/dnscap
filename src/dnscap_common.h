#include <netinet/in.h>

/*
 * setup MY_BPFTIMEVAL as the timeval structure that bpf packets
 * will be assoicated with packets from libpcap
 */
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
 * plugins can call these function in the main dnscap
 * process.
 */
typedef int logerr_t(const char *fmt, ...);
typedef int is_responder_t(iaddr);
typedef struct {
	logerr_t *logerr;
	is_responder_t *is_responder;
} plugin_callbacks;

/*
 * Prototype for the plugin "output" function
 */
typedef void output_t(const char *descr,
        iaddr from,
        iaddr to,
        uint8_t proto,
        unsigned flags,
        unsigned sport,
        unsigned dport,
        my_bpftimeval ts,
        const u_char *pkt_copy,
        const unsigned olen,
        const u_char *payload,
        const unsigned payloadlen);


typedef int plugin_start_t(plugin_callbacks *);
typedef void plugin_stop_t(void);
typedef int plugin_open_t(my_bpftimeval);
typedef int plugin_close_t(my_bpftimeval);
typedef output_t plugin_output_t;
typedef void plugin_getopt_t(int *, char **[]);
typedef void plugin_usage_t(void);

#define DNSCAP_OUTPUT_ISFRAG (1<<0)
#define DNSCAP_OUTPUT_ISDNS (1<<1)

#define DIR_INITIATE	0x0001
#define DIR_RESPONSE	0x0002
