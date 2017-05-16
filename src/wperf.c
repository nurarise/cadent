#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include <pthread.h>

#include "wperf.h"
#include "report.h"

#define MAX_CIRBUF_SZ      2048	//2K bytes

/*
*       struct scan_result: structure for store the scan result.
*
*       @freq:          frequency on which the given ssid is matched.
*       @bitrate:       bitrate calculated through rssi by radio
*       @linkq:         link quality in percentage.
*       @signallevel:   received signal level
*       @noiselevel:    noise level at receiver.
*/
typedef struct scan_result
{
        uint32_t        freq;
        uint32_t        bitrate;
        uint32_t        linkq;
        uint32_t        signallevel;
        uint32_t        noiselevel;
}StSResult;

/**
*	struct cmsg_q:	circular message queue structure to store the rssi value
*		rssi value will be enqueue periodically through scan result.
*		and dequeue through dispaly function to display the rssi histogram.
*
*	@front:	front index of circular queue.
*	@rear:	rear index of circular queue.
*	@qlen:	circular queue length.
*	@buf:	buffer pointer for linear array.
*/
struct cmsg_q
{
	  int        	front;
	  int        	rear;
	  int        	qlen;
	  uint32_t	*buf;
};

/*
*	struct wperf_ctx: context structure for wperf tool
*
*	@nlsock:	socket descriptor of netlink socket.
*	@nl80211id:	nl80211 identifier from the netlink interface.
*	@nlmsglen:	netlink message length of netlink message buffer.
*	@msgq:		circular queue to store the receiver signal strength indicator(rssi).
*	@stid:		thread id for getting the scan result.
*	@dtid:		thread id for reading and send the information to display function.
*	@lock:		lock for synchronise the circular message queue.
*	@ssid:		ssid to find the dead spot.
*	@ifname:	wifi interface used for monitor.
*/
struct wperf_ctx
{
	struct nl_sock	*nlsock;
	int		nl80211id;
	int		nlmsglen;
	struct cmsg_q	*msgq;
	pthread_t	stid;
	pthread_t	dtid;
	pthread_mutex_t	lock;
	char 		*ssid;
	char		*ifname;
};


/**
 * struct nlmsg_attribute: attributes to nla_put into the message
 *
 * @type:       type of the attribute
 * @len:        attribute length
 * @data:       pointer to data area of length @len
 */
struct nlmsg_attribute {
        int             type,
                        len;
        const void      *data;
};

/**
 * struct wireless_cmd - inspired from iw:iw.h & wavemon
 * @nlcmd:        nl80211 command to send via GeNetlink
 * @handler:      netlink callback handler
 * @handler_arg:  argument for @handler
 * @msg_args:     additional attributes to pass into message
 * @msg_args_len: number of elements in @msg_args
 * @flags:	  flags to set in the GeNetlink message
*/
struct wireless_cmd {
        enum nl80211_commands   nlcmd;
        int (*nl_handler)(struct nl_msg *msg, void *arg);
        void                    *handler_arg;

        struct nlmsg_attribute    *msg_args;
        uint8_t                  msg_args_len;
	int                     flags;
};

static int msg_enqueue(struct wperf_ctx *state, const uint32_t data)
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

static int msg_dequeue(struct wperf_ctx *state, uint32_t *data)
{
  struct cmsg_q *msgq = state->msgq;

  pthread_mutex_lock(&state->lock);
	if ( msgq->front == msgq->rear)
	{
		fprintf(stderr, "msgq is empty\n");
		pthread_mutex_unlock(&state->lock);
		return -1;
	}else if ( msgq->front == msgq->qlen)
		msgq->front = 0;
	memcpy(data, &msgq->buf[msgq->front], sizeof(uint32_t));
        (void)data;
	msgq->front++;

  printf("msg_dequeue: front: %d, rear: %d, data:%d\n", msgq->front, msgq->rear, *data);
  pthread_mutex_unlock(&state->lock);

  return 0;
}

static int nlsocket_open(struct wperf_ctx *state)
{
  int ret = 0;
  int nlmsglen;

  /*create the new netlink socket interface*/
  state->nlsock = nl_socket_alloc();
  if (state->nlsock == NULL)
  {
     fprintf(stderr, "fail to allocate the netlink socket: %d\n", errno);
     return -ENOMEM;
  }

  /*connect the new socket interface with generic netlink*/
  ret = genl_connect(state->nlsock);
  if(ret)
  {
     fprintf(stderr, "fail to connect to generic netlink: %d\n", errno);
     ret = -ENOLINK;
     goto nlsocket_cleanup;
  }

  /*default nl message size defined as 8192 bytes*/
  nlmsglen = sysconf(_SC_PAGESIZE) <=0 ? 8192 : sysconf(_SC_PAGESIZE)*2;

  /*define the size of the buffer for netlink commnucation, tx/rx*/
  nl_socket_set_buffer_size(state->nlsock, nlmsglen, nlmsglen);

  /*resolve the generic netlink interface with nl80211 service*/
  state->nl80211id = genl_ctrl_resolve(state->nlsock, "nl80211");

  if (state->nl80211id < 0)
  {
     fprintf(stderr, "fail to resolve the nl80211 on netlink service\n");
     ret = -ENOENT;
     goto nlsocket_cleanup;
  }

  return 0;

  nlsocket_cleanup:
        nl_socket_free(state->nlsock);
        return ret;
}

static void nlsocket_destroy(struct wperf_ctx *state)
{
  /*close the new allocated socket inetrface*/
  nl_socket_free(state->nlsock);
}

static int nl80211cmd_handle(struct wireless_cmd *cmd, struct wperf_ctx *state)
{
	int ret;
	uint32_t ifindex, idx;
        struct nl_cb *cb;
        struct nl_msg *msg;

        ifindex = if_nametoindex(state->ifname);
        if (ifindex == 0 && errno)
	{
                fprintf(stderr, "failed to look up interface %s", state->ifname);
		return -1;
	}

        /*
         * Message Preparation
         */
        msg = nlmsg_alloc();
        if (!msg)
	{
                fprintf(stderr, "failed to allocate netlink message");
		return -1;
	}

        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb)
	{
                fprintf(stderr, "failed to allocate netlink callback");
		return -1;
	}

        genlmsg_put(msg, 0, 0, state->nl80211id, 0, cmd->flags, cmd->cmd, 0);

        /* netdev identifier: interface index */
        NLA_PUT(msg, NL80211_ATTR_IFINDEX, sizeof(ifindex), &ifindex);

        /* Additional attributes */
        if (cmd->msg_args) {
                for (idx = 0; idx < cmd->msg_args_len; idx++)
                        NLA_PUT(msg, cmd->msg_args[idx].type,
                                     cmd->msg_args[idx].len,
                                     cmd->msg_args[idx].data);
        }

        ret = nl_send_auto_complete(state>nlsock, msg);
        if (ret < 0)
        {
		fprintf(stderr, "failed to send netlink message");
		return -1;
        }

        /*-------------------------------------------------------------------------
         * Receive loop
         *-------------------------------------------------------------------------*/
        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
        if (cmd->handler)
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cmd->handler, cmd->handler_arg);

        while (ret > 0)
                nl_recvmsgs(cmd->sk, cb);

        nl_cb_put(cb);
        nlmsg_free(msg);

        return ret;
}

static int iw_nl80211_scan_trigger(struct wperf_ctx *state)
{
        static struct wireless_cmd cmd_trigger_scan = {
                .cmd = NL80211_CMD_TRIGGER_SCAN,
        };

        return nl80211_handle(&cmd_trigger_scan, state);
}


static int get_scanresult(struct wperf_ctx *state, StScanResult *result)
{
	int ret;

	ret = iw_nl80211_scan_trigger();

	if( !ret || ret == EBUSY)
	{

	}
	else
	{
		fprintf(stderr, "scan trigger fail, check for the wireless interface");
		return -1;
	}

	return 0;
}


static void *wperf_scanthread(void *vstate )
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


static int wperf_init(struct wperf_ctx *state, const char *ssid, const char *ifname)
{
	int ret;
	struct cmsg_q mq = { .front = 0,
			.rear = 0,
			.qlen = MAX_CIRBUF_SZ,
			.buf  = NULL};
	char ssidbuf[] = *ssid, ifbuf[] = *ifname;

	mq.buf = malloc(qlen);
        if(mq.buf == NULL) return -ENOMEM;

	state->msgq = malloc(sizeof(mq));
        if(state->msgq == NULL) return -ENOMEM;

	state->ssid = malloc(sizeof(ssidbuf));
        if(state->ssid == NULL) return -ENOMEM;

	state->ifname = malloc(sizeof(ifbuf));
	if(state->ifname == NULL) return -ENOMEM;

	memcpy(state->msgq, &mq, sizeof(mq));

	/*create the mutex lock*/
	if(pthread_mutex_init(&state->lock, NULL)){
		fprintf(stderr, "fail to create the pthred_mutex_init, error:%d\n", errno);
		goto cleanup_wperf;
	}

	ret = nlsocket_open(state);
	if(ret){
		fprintf(stderr, "nlsocket fail to open, error: %d", ret);
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
	struct wperf_ctx *state = NULL;

	fprintf(stderr, "wperf: for ssid:%s over ifname: %s\n", ssid, ifname);
	if (ssid == NULL || ifname == NULL){
		fprintf(stderr, "parameter error, null pointer passed\n");
		return -1;
	}

	state  = malloc(sizeof(struct wperf_ctx));
	if (state == NULL){
		fprintf(stderr, "fail to allocate the memeory for nlstate\n");
		return -1;
	}
	if (wperf_init(state, ssid, ifname)){
		free(state);
		return -1;
	}

	while(1); //run the thread forever till receive the terminate signal.
	return 0;
}
