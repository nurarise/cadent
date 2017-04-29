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

struct wperf_nlstate
{
 struct nl_sock *nlsock;
 int nl80211id;
};

static int wperf_nlopen(struct wperf_nlstate *state)
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
     goto wperf_cleanup;
  }

  nlmsglen = sysconf(_SC_PAGESIZE) <=0 ? 8192 : sysconf(_SC_PAGESIZE)*2;

  /*define the size of the buffer for netlink commnucation, tx/rx*/
  nl_socket_set_buffer_size(state->nlsock, nlmsglen, nlmsglen);

  /*resolve the generic netlink interface with nl80211 service*/
  state->nl80211id = genl_ctrl_resolve(state->nlsock, "nl80211");
  if (state->nl80211id < 0)
  {
     fprintf(stderr, "fail to resolve the nl80211 on netlink service\n");
     ret = -ENOENT;
     goto wperf_cleanup;
  }

  return 0;

  wperf_cleanup:
      nl_socket_free(state->nlsock);
      return ret;
}

static void wperf_nlclose(struct wperf_nlstate *state)
{
  /*close the new allocated socket inetrface*/
  nl_socket_free(state->nlsock);
}

int wperf(const char *ssid, const char *ifname)
{
  struct wperf_nlstate *nl = NULL;

  fprintf(stderr, "wperf: for ssid:%s over ifname: %s\n", ssid, ifname);
  if (ssid == NULL || ifname == NULL)
  {
     fprintf(stderr, "parameter error, null pointer passed\n");
     return -1;
  }

  nl  = malloc(sizeof(struct wperf_nlstate));
  if (nl == NULL)
  {
     fprintf(stderr, "fail to allocate the memmeory for nlstate\n");
     return -1;
  }

  if (wperf_nlopen(nl))
     return -1;

  wperf_nlclose(nl);
  free(nl);
  return 0;
}
