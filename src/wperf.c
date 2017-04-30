#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>
#include <pthread.h>

#define MAX_CIRBUF_SZ      2048   //2K bytes
typedef char  perfdata_t;   //FIXME: change the data type later, based on data to process.

struct cmsg_q
{
  int        front;
  int        rear;
  int        qlen;
  perfdata_t buf[MAX_CIRBUF_SZ];
};

struct wperf_ctx
{
 struct nl_sock *nlsock;
 int             nl80211id;
 int             nlmsglen;
 struct cmsg_q  *msgq;
 pthread_t       tid;
 pthread_mutex_t lock;
}wperf_ctx;

static int msg_enqueue(struct wperf_ctx *state, const perfdata_t data)
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
  pthread_mutex_unlock(&state->lock);

  return 0;
}

static int msg_dequeue(struct wperf_ctx *state, perfdata_t *data)
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
	data = &msgq->buf[msgq->front];
        (void)data;
	msgq->front++;
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

static void *wperf_scanthread(void *vstate )
{
  struct wperf_ctx *state = vstate;
  perfdata_t data;

  while (1) {
      /*FIXME:get the active scan data via nl80211 message*/
      msg_enqueue(state, random());
      sleep(5);
      msg_dequeue(state, &data);
      fprintf(stdout, "msg: %d\n", data);
 }
 return NULL;
}


static int wperf_init(struct wperf_ctx *state)
{
   int ret;
   struct cmsg_q mq = { .front = 0,
			.rear = 0,
			.qlen = MAX_CIRBUF_SZ,
			.buf  = {0}};

   state->msgq = malloc(sizeof(mq));
   if(state->msgq == NULL)
   {
      fprintf(stderr, "fail to allocate the msgq struct\n");
      return -ENOMEM;
   }

   memcpy(state->msgq, &mq, sizeof(mq));

   /*create the mutex lock*/
   if(pthread_mutex_init(&state->lock, NULL))
   {
      fprintf(stderr, "fail to create the pthred_mutex_init, error:%d\n", errno);
      free(state->msgq);
      return -1;
   }

   ret = nlsocket_open(state);
   if(ret)
   {
      fprintf(stderr, "nlsocket fail to open, error: %d", ret);
      nlsocket_destroy(state);
      pthread_mutex_destroy(&state->lock);
      free(state->msgq);
      return -1;
   }

   ret = pthread_create(&state->tid, NULL, wperf_scanthread, state);
   if(ret)
   {
      fprintf(stderr, "fail to create the pthread, error:%d\n", errno);
      nlsocket_destroy(state);
      pthread_mutex_destroy(&state->lock);
      free(state->msgq);
      return -1;
   }

   return 0;
}


int wperf(const char *ssid, const char *ifname)
{
  struct wperf_ctx *state = NULL;

  fprintf(stderr, "wperf: for ssid:%s over ifname: %s\n", ssid, ifname);
  if (ssid == NULL || ifname == NULL)
  {
     fprintf(stderr, "parameter error, null pointer passed\n");
     return -1;
  }

  state  = malloc(sizeof(struct wperf_ctx));
  if (state == NULL)
  {
     fprintf(stderr, "fail to allocate the memeory for nlstate\n");
     return -1;
  }

  if (wperf_init(state))
     return -1;

  return 0;
}
