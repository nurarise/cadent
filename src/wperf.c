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
	if(((msgq->rear + 1) == msgq->front) || ((msgq->rear - msgq->qlen) == msgq->front))
	{
		fprintf(stderr, "msg queue is full\n");
                pthread_mutex_unlock(&state->lock);
		return -1;
	}else if (msgq->rear == msgq->qlen)
		msgq->rear = 0;
	memcpy(&msgq->buf[msgq->rear], &data, sizeof(msgq->buf[0]));
	msgq->rear++;
  /*Debug log*/
  printf("msg_enqueue: front: %d, rear: %d, data:%d\n", msgq->front, msgq->rear, data);
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
#if DEBUG > 1
	printf("msg_dequeue: front: %d, rear: %d, data:%d\n", msgq->front, msgq->rear, *data);
#endif
	pthread_mutex_unlock(&state->lock);

	return 0;
}

static int iw_nl80211_scan_trigger(struct wperf_ctx *state)
{
        static struct wireless_cmd cmd_trigger_scan = {
                .nlcmd = NL80211_CMD_TRIGGER_SCAN,
        };

        return nl80211cmd_handle(&cmd_trigger_scan, state);
}


static int get_scanresult(struct wperf_ctx *state, StScanResult *result UNUSED)
{
	int ret;

	ret = iw_nl80211_scan_trigger(state);

	if( !ret || ret == EBUSY)
	{

	}
	else
	{
		fprintf(stderr, "scan trigger fail, check for the wireless interface\n");
		return -1;
	}

	return 0;
}


static void *wperf_scanthread(void *vstate)
{
	struct wperf_ctx *state = vstate;
	struct StScanResult *sresult;

	sresult = malloc(sizeof(*sresult));
	if(!sresult)
	{
		fprintf(stderr, "fail to allocate the memory @%s\n", __FUNCTION__);
		exit(1); //terminate the thread;
	}
	while (1) {
		if(get_scanresult(state, sresult))
		{
			fprintf(stderr, "netlink error: exit the scan thread\n");
			exit(1);
		}
		msg_enqueue(state, sresult->linkq); // FIXME: monitor receiver signal strength indicator
	}
	return NULL;
}

static void *wperf_reportthread(void *vstate)
{
	struct wperf_ctx *state UNUSED = vstate;
	uint32_t data;

	while(1)
	{
		msg_dequeue(state, &data);
	}
	return NULL;
}

static int init(struct wireless_ctx *state, const char *ssid, const char *ifname)
{
	int ret;
	uint32_t ifindex;
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
	if(pthread_mutex_init(&state->lock, NULL)){
		fprintf(stderr, "fail to create the pthred_mutex_init, error:%d\n", errno);
		goto cleanup_wperf;
	}

	ret = nlsocket_open(state);
	if(ret){
		fprintf(stderr, "nlsocket fail to open, error: %d\n", ret);
		goto cleanup_wperf;
	}

        ifindex = if_nametoindex(state->ifname);
        if (ifindex == 0 && errno)
        {
                fprintf(stderr, "failed to look up interface %s\n", state->ifname);
                return -1;
        }

        /*create the mutex lock*/
        if(pthread_mutex_init(&state->lock, NULL)){
                fprintf(stderr, "fail to create the pthred_mutex_init, error:%d\n", errno);
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
		goto cleanup_wperf;
	}
	return 0;

cleanup_wperf:
	nlsocket_destroy(state);
	pthread_mutex_destroy(&state->lock);
	free(mq.buf);
	free(state->msgq);

	return -1;

}


int wireless_perf(const char *ssid, const char *ifname)
{
	struct wireless_ctx *state = NULL;

	fprintf(stdout, "wperf: for ssid:%s over ifname: %s\n", ssid, ifname);
	if (ssid == NULL || ifname == NULL){
		fprintf(stderr, "parameter error, null pointer passed\n");
		return -1;
	}

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
