#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include <pthread.h>

#include "iw_cmd.h"
#include "report.h"

#define MAX_CIRBUF_SZ      2048	//2K bytes
#define UNUSED             __attribute__((unused))

/* GLOBAL VARIABLES */
static struct nl_sock *scan_wait_sk;

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
	  uint32_t	*buf;
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


static int msg_enqueue(struct wireless_ctx *state, const uint32_t data)
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

	memcpy(&msgq->buf[msgq->rear], &data, sizeof(msgq->buf[0]));
	msgq->rear++;

#if DEBUG_LEVEL > 1
	/*Debug log*/
	printf("msg_enqueue: front: %d, rear: %d, data:%d\n", msgq->front, msgq->rear, data);
#endif

	pthread_mutex_unlock(&state->lock);

	return 0;
}

static int msg_dequeue(struct wireless_ctx *state, uint32_t *data)
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

	memcpy(data, &msgq->buf[msgq->front], sizeof(*data));
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

        cb = nl_cb_alloc(IW_NL_CB_DEBUG ? NL_CB_DEBUG : NL_CB_DEFAULT);
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

/**
 * Scan result handler. Stolen from iw:scan.c
 * This also updates the scan-result statistics.
 */
int scan_dump_handler(struct nl_msg *msg, void *arg)
{
        struct scan_result *sr = (struct scan_result *)arg;
        struct scan_entry *new = calloc(1, sizeof(*new));
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

        new = calloc(1, sizeof(*new));
        if (!new)
                err_sys("failed to allocate scan entry");

        memcpy(&new->ap_addr, nla_data(bss[NL80211_BSS_BSSID]), sizeof(new->ap_addr));

        if (bss[NL80211_BSS_FREQUENCY]) {
                new->freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
                new->chan = ieee80211_frequency_to_channel(new->freq);
        }
       if (bss[NL80211_BSS_SIGNAL_UNSPEC])
                new->bss_signal_qual = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);


        if (bss[NL80211_BSS_SIGNAL_MBM]) {
                int s = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
                new->bss_signal = s / 100;
        }

        if (bss[NL80211_BSS_CAPABILITY]) {
                new->bss_capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
                new->has_key  = (new->bss_capa & WLAN_CAPABILITY_PRIVACY) != 0;
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
                                if (len > 0 && len <= 32)
                                        print_ssid_escaped(new->essid, sizeof(new->essid),
                                                           ie+2, len);
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

        /* Update stats */
        new->next = sr->head;
        sr->head  = new;
       if (str_is_ascii(new->essid))
                sr->max_essid_len = clamp(strlen(new->essid),
                                          sr->max_essid_len,
                                          IW_ESSID_MAX_SIZE);

        if (new->freq > 45000)  /* 802.11ad 60GHz spectrum */
                err_quit("FIXME: can not handle %d MHz spectrum yet", new->freq);
        else if (new->freq >= 5000)
                sr->num.five_gig++;
        else if (new->freq >= 2000)
                sr->num.two_gig++;
        sr->num.entries += 1;
        sr->num.open    += !new->has_key;

        return NL_SKIP;
}

static int iw_nl80211_scan_trigger(struct wireless_ctx *state)
{
        static struct wireless_cmd cmd_trigger_scan = {
                .nlcmd = NL80211_CMD_TRIGGER_SCAN,
        };

        return nl80211cmd_handle(&cmd_trigger_scan);
}

static int iw_nl80211_get_scan_data(struct scan_result *sr)
{
        static struct cmd cmd_scan_dump = {
                .nlcmd     = NL80211_CMD_GET_SCAN,
                .flags   = NLM_F_DUMP,
                .nl_handler = scan_dump_handler
        };

        memset(sr, 0, sizeof(*sr));
        cmd_scan_dump.handler_arg = sr;

        return nl80211cmd_handle(&cmd_scan_dump);
}

static int get_scanresult(struct wireless_ctx *state, scan_result *result)
{
	int ret;

	ret = iw_nl80211_scan_trigger(state);

	if( !ret || ret == EBUSY){
	/* Trigger returns -EBUSY if a scan request is pending or ready. */
		if (!iw_nl80211_wait_for_scan_events()) {
			printf(stdout, "Waiting for scan data...");
		} else {
			ret = iw_nl80211_get_scan_data(result);
			if (ret < 0) {
				printf(stderr,"Scan failed on %s: %s", state->ifname, strerror(-ret));
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
	struct scan_result *sresult;

	sresult = malloc(sizeof(*sresult));
	if(!sresult){
		fprintf(stderr, "fatal: fail to allocate the memory @%s\n", __FUNCTION__);
		exit(1); //terminate the application
	}
	while (1) {
		if(get_scanresult(state, sresult)) {
			fprintf(stderr, "fatal:netlink error: exit the scan thread\n");
			exit(1);
		}
		msg_enqueue(state, sresult->linkq); // FIXME: monitor receiver signal strength indicator
		usleep(1000);
	}
	return NULL;
}

static void *wperf_reportthread(void *vstate)
{
	struct wperf_ctx *state = vstate;
	uint32_t data;

	while(1){
		msg_dequeue(state, &data);
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

	mq.buf = malloc(mq.qlen);
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
