#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include <pthread.h>

#include "iw_cmd.h"
#include "report.h"

#define MAX_CIRBUF_SZ      2048	//2K bytes
#define UNUSED             __attribute__((unused))
#define ARRAY_SIZE(arr)		sizeof(arr)/sizeof((arr)[0])

/* GLOBAL VARIABLES */
static struct nl_sock *scan_wait_sk;
//static char gssid[IW_ESSID_MAX_SIZE+1];
static bool foundssid = false;

/**
* struct cmsg_q:	circular message queue structure to store the rssi value
*	rssi value will be enqueue periodically through scan result.
*	and dequeue through dispaly function to display the rssi histogram.
*
* front:	front index of circular queue.
* rear:	rear index of circular queue.
* qlen:	circular queue length.
* buf:	buffer pointer for linear array.
*/
struct cmsg_q {
	  int        	front;
	  int        	rear;
	  int        	qlen;
	  void		*buf;
};

/*
* struct wireless_ctx: context structure for wireless tool
*
* msgq:	circular queue to store the receiver signal strength indicator(rssi).
* stid:	thread id for getting the scan result.
* dtid:	thread id for reading and send the information to display function.
* lock:	lock for synchronise the circular message queue.
* ssid:	ssid to find the dead spot.
* ifname: wifi interface used for monitor.
*/
struct wireless_ctx {
	struct cmsg_q	*msgq;
	pthread_t	stid;
	pthread_t	dtid;
	pthread_mutex_t	lock;
	char 		*ssid;
	char		*ifname;
};

/**
 * struct wait_event - wait for arrival of a specified message
 * @cmds:   array of GeNetlink commands (>0) to match
 * @n_cmds: length of @cmds
 * @cmd:    matched element of @cmds (if message arrived), else 0
 */
struct wait_event {
        const uint32_t  *cmds;
        uint8_t         n_cmds;
        uint32_t        cmd;
};

static int msg_enqueue(struct wireless_ctx *state, const struct scan_result data)
{
	struct cmsg_q *msgq = state->msgq;

	pthread_mutex_lock(&state->lock);
	if(((msgq->rear + 1) == msgq->front) || ((msgq->rear - msgq->qlen) == msgq->front)){
		fprintf(stderr, "msg queue is full\n");
		pthread_mutex_unlock(&state->lock);
		return -1;
	}else if (msgq->rear == msgq->qlen){
		msgq->rear = 0;
	}

	memcpy( (struct scan_result *)msgq->buf + msgq->rear, &data, sizeof(struct scan_result));
	msgq->rear++;

#if DEBUG_LEVEL > 1
	/*Debug log*/
	printf("msg_enqueue: front: %d, rear: %d, data:%d\n", msgq->front, msgq->rear, data);
#endif

	pthread_mutex_unlock(&state->lock);

	return 0;
}

static int msg_dequeue(struct wireless_ctx *state, struct scan_result *data)
{
	struct cmsg_q *msgq = state->msgq;

	pthread_mutex_lock(&state->lock);

	if ( msgq->front == msgq->rear) {
		fprintf(stderr, "msgq is empty\n");
		pthread_mutex_unlock(&state->lock);
		return -1;
	}else if ( msgq->front == msgq->qlen) {
		msgq->front = 0;
	}

	memcpy(data, (struct scan_result *)msgq->buf + msgq->front, sizeof(struct scan_result));
	msgq->front++;
#if DEBUG_LEVEL > 1
	printf("msg_dequeue: front: %d, rear: %d, data:%d\n", msgq->front, msgq->rear, *data);
#endif
	pthread_mutex_unlock(&state->lock);

	return 0;
}

/*
 * Scan event handling
 */

int ieee80211_frequency_to_channel(int freq)
{
        /* see 802.11-2007 17.3.8.3.2 and Annex J */
        if (freq == 2484)
                return 14;
        else if (freq < 2484)
                return (freq - 2407) / 5;
        else if (freq >= 4910 && freq <= 4980)
                return (freq - 4000) / 5;
        else if (freq <= 45000) /* DMG band lower limit */
                return (freq - 5000) / 5;
        else if (freq >= 58320 && freq <= 64800)
                return (freq - 56160) / 2160;
        else
                return 0; 
}

/* Callback event handler */
static int wait_event(struct nl_msg *msg, void *arg)
{
        struct wait_event *wait = arg;
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        int i;

        for (i = 0; i < wait->n_cmds; i++) {
                if (gnlh->cmd == wait->cmds[i])
                        wait->cmd = gnlh->cmd;
        }
        return NL_SKIP;
}

static inline int no_seq_check(struct nl_msg *msg UNUSED, void *arg UNUSED)
{
        return NL_OK;
}

/**
 * Wait for scan result notification sent by the kernel
 * Returns true if scan results are available, false if scan was aborted.
 * Taken from iw:event.c:__do_listen_events
 */
static bool iw_nl80211_wait_for_scan_events(void)
{
        static const uint32_t cmds[] = {
                NL80211_CMD_NEW_SCAN_RESULTS,
                NL80211_CMD_SCAN_ABORTED,
        };
        struct wait_event wait_ev = {
                .cmds   = cmds,
                .n_cmds = ARRAY_SIZE(cmds),
                .cmd    = 0
        };
        struct nl_cb *cb;

        if (!scan_wait_sk)
                scan_wait_sk = alloc_nl_mcast_sk("scan");

        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb){
		fprintf(stderr, "fatal:failed to allocate netlink callbacks");
		return -1;
	}

        /* no sequence checking for multicast messages */
        nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, wait_event, &wait_ev);

        while (!wait_ev.cmd)
                nl_recvmsgs(scan_wait_sk, cb);
        nl_cb_put(cb);

        return wait_ev.cmd == NL80211_CMD_NEW_SCAN_RESULTS;
}

void print_ssid_escaped(char *buf, const size_t buflen,
                        const uint8_t *data, const size_t datalen)
{
        unsigned int i, l;

        memset(buf, '\0', buflen);      
        /* Treat zeroed-out SSIDs separately */
        for (i = 0; i < datalen && data[i] == '\0'; i++)
                ; 
        if (i == datalen)
                return; 

        for (i = l= 0; i < datalen; i++) {
                if (l + 4 >= buflen)
                        return;
                else if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
                        l += sprintf(buf + l, "%c", data[i]);
                else if (data[i] == ' ' && i != 0 && i != datalen -1)
                        l += sprintf(buf + l, " ");
                else
                        l += sprintf(buf + l, "\\x%.2x", data[i]);
        }
}


/**
 * Scan result handler. Stolen from iw:scan.c
 * This also updates the scan-result statistics.
 */
int scan_dump_handler(struct nl_msg *msg, void *arg)
{
        struct scan_result temp, *result = (struct scan_result *)arg;
        struct scan_result *new = (struct scan_result *)&temp;
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        struct nlattr *bss[NL80211_BSS_MAX + 1];
        static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
                [NL80211_BSS_TSF]                  = { .type = NLA_U64 },
                [NL80211_BSS_FREQUENCY]            = { .type = NLA_U32 },
                [NL80211_BSS_BSSID]                = { },
                [NL80211_BSS_BEACON_INTERVAL]      = { .type = NLA_U16 },
                [NL80211_BSS_CAPABILITY]           = { .type = NLA_U16 },
                [NL80211_BSS_INFORMATION_ELEMENTS] = { },
                [NL80211_BSS_SIGNAL_MBM]           = { .type = NLA_U32 },
                [NL80211_BSS_SIGNAL_UNSPEC]        = { .type = NLA_U8  },
                [NL80211_BSS_STATUS]               = { .type = NLA_U32 },
                [NL80211_BSS_SEEN_MS_AGO]          = { .type = NLA_U32 },
                [NL80211_BSS_BEACON_IES]           = { },
        };

	//printf("scan_dump_handler\n");

        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[NL80211_ATTR_BSS])
                return NL_SKIP;

        if (nla_parse_nested(bss, NL80211_BSS_MAX,
                             tb[NL80211_ATTR_BSS],
                             bss_policy))
                return NL_SKIP;

        if (!bss[NL80211_BSS_BSSID])
                return NL_SKIP;

        memcpy(&new->ap_addr, nla_data(bss[NL80211_BSS_BSSID]), sizeof(new->ap_addr));

        if (bss[NL80211_BSS_FREQUENCY]) {
                new->freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
                new->chan = ieee80211_frequency_to_channel(new->freq);
        }
       if (bss[NL80211_BSS_SIGNAL_UNSPEC]){
                new->bss_signal_qual = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
		printf("Signal Qual: %d\n", new->bss_signal_qual);
	}

        if (bss[NL80211_BSS_SIGNAL_MBM]) {
                int s = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
		//printf("signal: %d\n", s);
                new->bss_signal = s / 100;
        }

        if (bss[NL80211_BSS_CAPABILITY]) {
                new->bss_capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
                //new->has_key  = (new->bss_capa & WLAN_CAPABILITY_PRIVACY) != 0;
        }

        if (bss[NL80211_BSS_SEEN_MS_AGO])
                new->last_seen = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);

        if (bss[NL80211_BSS_TSF])
                new->tsf = nla_get_u64(bss[NL80211_BSS_TSF]);

        if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
                uint8_t *ie = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
                int ielen   = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
                uint8_t len = ie[1];

                while (ielen >= 2 && ielen >= ie[1]) {
                        switch (ie[0]) {
                        case 0: /* SSID */
                                if (len > 0 && len <= 32) {
                                        print_ssid_escaped(new->essid, sizeof(new->essid),
                                                           ie+2, len);
					//printf("ssid: %s\n", new->essid);
					}
                                break;
                        case 11: /* BSS Load */
                                if (len >= 5) {
                                        new->bss_sta_count  = ie[3] << 8 | ie[2];
                                        new->bss_chan_usage = ie[4];
                                }
                                break;
                        }
                        ielen -= ie[1] + 2;
                        ie    += ie[1] + 2;
                }
        }
	if(!strcmp(new->essid, result->essid) && !foundssid) {
		memcpy(result, new, sizeof(*result));
		printf("hurrah!!!, found %s AP\n", new->essid);
		foundssid = true;
	}
        return NL_SKIP;
}

static int iw_nl80211_scan_trigger(const char *ssid)
{
//	static struct nlmsg_attribute attr = {
//		.type = NL80211_ATTR_SCAN_SSIDS,
//	};
        static struct nl80211_cmd cmd_trigger_scan = {
                .nlcmd = NL80211_CMD_TRIGGER_SCAN,
        };
	printf("scan trigger: ssid: %s\n", ssid);
	//attr.len = strlen(ssid) + 1;
	//attr.data = ssid;
	//cmd_trigger_scan.msg_args = &attr;
	//cmd_trigger_scan.msg_args_len = 1;

	return nl80211cmd_handle(&cmd_trigger_scan);
}

static int iw_nl80211_get_scan_data(struct scan_result *sr, const char *ssid)
{
        static struct nl80211_cmd cmd_scan_dump = {
                .nlcmd     = NL80211_CMD_GET_SCAN,
                .flags   = NLM_F_DUMP,
                .nl_handler = scan_dump_handler
        };

        memset(sr, 0, sizeof(*sr));
	strncpy(sr->essid,ssid, sizeof(sr->essid));
	foundssid = false;

        cmd_scan_dump.handler_arg = sr;

        return nl80211cmd_handle(&cmd_scan_dump);
}

static int get_scanresult(struct wireless_ctx *state, struct scan_result *result)
{
	int ret;

	ret = iw_nl80211_scan_trigger(state->ssid);

	if( !ret || ret == EBUSY){
	/* Trigger returns -EBUSY if a scan request is pending or ready. */
		if (!iw_nl80211_wait_for_scan_events()) {
			printf("Waiting for scan data...");
		} else {
			ret = iw_nl80211_get_scan_data(result, state->ssid);
			if (ret < 0) {
				fprintf(stderr,"Scan failed on %s: %s", state->ifname, strerror(-ret));
				return -1;
			}
		}
	}
	else{
		fprintf(stderr, "scan trigger fail, check for the wireless interface\n");
		return -1;
	}

	return 0;
}


static void *wperf_scanthread(void *vstate)
{
	struct wireless_ctx *state = vstate;
	struct scan_result sresult;

	while (1) {
		if(get_scanresult(state, &sresult)) {
			fprintf(stderr, "fatal:netlink error: exit the scan thread\n");
			exit(1);
		}
		msg_enqueue(state, sresult); // FIXME: monitor receiver signal strength indicator
		usleep(1000); // trigger the scan for every one sec
	}
	return NULL;
}

static void *wperf_reportthread(void *vstate)
{
	struct wireless_ctx *state = vstate;
	struct scan_result sr;
	int sig_qual_max,sig_qual;

	while(1){
		if(!msg_dequeue(state, &sr)){
			printf("essid %s\n", sr.essid);
			printf("freq: %d KHz\n", sr.freq);
			printf("chan: %d\n", sr.chan);
			printf("signal: %d dBm\n", sr.bss_signal); //signal level
		        if (sr.bss_signal_qual) {
				/* BSS_SIGNAL_UNSPEC is scaled 0..100 */
				sig_qual     = sr.bss_signal_qual;
				sig_qual_max = 100;
			} else if (sr.bss_signal) {
				if (sr.bss_signal < -110)
					sig_qual = 0;
				else if (sr.bss_signal > -40)
					sig_qual = 70;
				else
					sig_qual = sr.bss_signal + 110;
				sig_qual_max = 70;
			}
			printf("signal_qual %d/%d\n", sig_qual,sig_qual_max);
		}
		usleep(5000000); //run this thread every 5 sec
	}

	return NULL;
}

static int init(struct wireless_ctx *state, const char *ssid, const char *ifname)
{
	int ret;
	struct cmsg_q mq = { .front = 0,
			.rear = 0,
			.qlen = MAX_CIRBUF_SZ,
			.buf  = NULL};

	mq.buf = calloc(mq.qlen, sizeof(struct scan_result));
        if(mq.buf == NULL) 
		return -ENOMEM;

	state->msgq = malloc(sizeof(mq));
        if(state->msgq == NULL) 
		return -ENOMEM;

	memcpy(state->msgq, &mq, sizeof(mq));

	state->ssid = malloc(strlen(ssid)+1);
        if(state->ssid == NULL) 
		return -ENOMEM;

	strcpy(state->ssid, ssid);

	state->ifname = malloc(strlen(ifname)+1);
	if(state->ifname == NULL) 
		return -ENOMEM;

	strcpy(state->ifname, ifname);

	/*create the mutex lock*/
	if(pthread_mutex_init(&state->lock, NULL)) {
		fprintf(stderr, "fail to create the mutex lock\n");
		return -1;
	}
	

	ret = nlsocket_open(ifname);
	if(ret){
		fprintf(stderr, "nlsocket fail to open, error: %d\n", ret);
		goto cleanup_wperf;
	}

	ret = pthread_create(&state->stid, NULL, wperf_scanthread, state);
	if(ret){
		fprintf(stderr, "fail to create the pthread, error:%d\n", errno);
		goto cleanup_wperf;
	}

	ret = pthread_create(&state->dtid, NULL, wperf_reportthread, state);
	if(ret){
		fprintf(stderr, "fail to create the report thread:%d\n",errno);
		pthread_cancel(state->stid);
		goto cleanup_wperf;
	}

	return 0;

cleanup_wperf:
	nlsocket_destroy();
	pthread_mutex_destroy(&state->lock);
	free(mq.buf);
	free(state->msgq);

	return -1;

}


int wireless_perf(const char *ssid, const char *ifname)
{
	struct wireless_ctx *state = NULL;

	if (ssid == NULL || ifname == NULL){
		fprintf(stderr, "invalid parameter: ssid or ifname\n");
		return -1;
	}

	fprintf(stdout, "wperf: for ssid:%s over ifname: %s\n", ssid, ifname);

	state  = malloc(sizeof(*state));

	if (state == NULL){
		fprintf(stderr, "fail to allocate the memeory for nlstate\n");
		return -1;
	}
	if (init(state, ssid, ifname)){
		free(state);
		return -1;
	}

	while(1); //run the thread forever till receive the terminate signal.
	return 0;
}
