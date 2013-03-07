#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "../../dnscap_common.h"

static logerr_t *logerr;
static int opt_f = 0;
static const char *opt_x = 0;

output_t template_output;

void
template_usage()
{
	fprintf(stderr,
		"\ntemplate.so options:\n"
		"\t-f         flag option\n"
		"\t-x <arg>   option with argument\n"
		);
}

void
template_getopt(int *argc, char **argv[])
{
	/*
	 * The "getopt" function will be called from the parent to
	 * process plugin options.
	 */
	int c;
	while ((c = getopt(*argc, *argv, "fx:")) != EOF) {
		switch(c) {
		case 'f':
			opt_f = 1;
			break;
		case 'x':
			opt_x = strdup(optarg);
			break;
		default:
			template_usage();
			exit(1);
		}
	}
}

int
template_start(logerr_t *a_logerr)
{
	/*
	 * The "start" function is called once, when the program
	 * starts.  It is used to initialize the plugin.  If the
	 * plugin wants to write debugging and or error messages,
	 * it should save the a_logerr pointer passed from the
	 * parent code.
	 */
	logerr = a_logerr;
	return 0;
}

void
template_stop()
{
	/*
	 * The "start" function is called once, when the program
	 * is exiting normally.  It might be used to clean up state,
	 * free memory, etc.
	 */
}

int
template_open(my_bpftimeval ts)
{
	/*
	 * The "open" function is called at the start of each
	 * collection interval, which might be based on a period
	 * of time or a number of packets.  In the original code,
	 * this is where we opened an output pcap file.
	 */
	return 0;
}

int
template_close(my_bpftimeval ts)
{
	/*
	 * The "close" function is called at the end of each
	 * collection interval, which might be based on a period
	 * of time or on a number of packets.  In the original code
	 * this is where we closed an output pcap file.
	 */
	return 0;
}

void
template_output(const char *descr, iaddr from, iaddr to, uint8_t proto, int isfrag,
    unsigned sport, unsigned dport, my_bpftimeval ts,
    const u_char *pkt_copy, unsigned olen,
    const u_char *dnspkt, unsigned dnslen)
{
	/*
	 * Here you can "process" a packet.  The function is named
	 * "output" because in the original code this is where
	 * packets were outputted.
	 *
	 * Note that dnspkt may be NULL if the IP packet does not
	 * appear to contain a valid DNS message.
	 */
}
