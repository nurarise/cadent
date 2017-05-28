#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "iw_cmd.h"

#define UNUSED             __attribute__((unused))

/**
 * struct nlmsg_attribute: attributes to nla_put into the message
 *
 * type:       type of the attribute
 * len:        attribute length
 * data:       pointer to data area of length @len
 */
struct nlmsg_attribute {
        int             type,
                        len;
        const void      *data;
};

static struct nl80211_ctx gnlstate;

static inline int error_handler(struct sockaddr_nl *nla UNUSED, struct nlmsgerr *err,
                         void *arg)
{
        int *ret = arg;
        *ret = err->error;
        return NL_STOP;
}

static inline int finish_handler(struct nl_msg *msg UNUSED, void *arg)
{
        int *ret = arg;
        *ret = 0;       
        return NL_SKIP; 
}       

static inline int ack_handler(struct nl_msg *msg UNUSED, void *arg)
{
        int *ret = arg;
        *ret = 0;
        return NL_STOP;
}

static inline int no_seq_check(struct nl_msg *msg UNUSED, void *arg UNUSED)
{
        return NL_OK;
}

int nlsocket_open(const char *ifname)
{
	int ret = 0;
	int nlmsglen;
	uint32_t ifindex;

	struct nl80211_ctx *state = &gnlstate;

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0 && errno)
	{
		fprintf(stderr, "failed to look up interface %s\n", ifname);
		return -1;
	}
	state->ifindex = ifindex;

	/*create the new netlink socket interface*/
	state->nlsock = nl_socket_alloc();
	if (state->nlsock == NULL) {
		fprintf(stderr, "fail to allocate the netlink socket: %d\n", errno);
		return -ENOMEM;
	}

	/*connect the new socket interface with generic netlink*/
	ret = genl_connect(state->nlsock);
	if(ret) {
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

	if (state->nl80211id < 0) {
		fprintf(stderr, "fail to resolve the nl80211 on netlink service\n");
		ret = -ENOENT;
		goto nlsocket_cleanup;
	}

	return 0;

nlsocket_cleanup:
	nl_socket_free(state->nlsock);
        return ret;
}

void nlsocket_destroy(void)
{
	struct nl80211_ctx *state = &gnlstate;

	/*close the new allocated socket inetrface*/
	nl_socket_free(state->nlsock);
}

int nl80211cmd_handle(struct nl80211_cmd *cmd)
{
        int ret;
        struct nl_cb *cb;
        struct nl_msg *msg;
	struct nl80211_ctx *state = &gnlstate;  

        /* 
         * Message Preparation
         */
        msg = nlmsg_alloc();
        if (!msg)
        {
                fprintf(stderr, "failed to allocate netlink message\n");
                return -1;
        }

        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb)
        {
                fprintf(stderr, "failed to allocate netlink callback\n");
                return -1;
        }

        genlmsg_put(msg, 0, 0, state->nl80211id, 0, cmd->flags, cmd->nlcmd, 0);

        /* netdev identifier: interface index */
        NLA_PUT(msg, NL80211_ATTR_IFINDEX, sizeof(state->ifindex), &state->ifindex);

        ret = nl_send_auto_complete(state->nlsock, msg);
        if (ret < 0)
        {
                fprintf(stderr, "failed to send netlink message\n");
                return -1;
        }

        /*-------------------------------------------------------------------------
         * Receive loop
         *-------------------------------------------------------------------------*/
        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
        if (cmd->nl_handler)
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, cmd->nl_handler, cmd->handler_arg);

        while (ret > 0)
                nl_recvmsgs(state->nlsock, cb);

        nl_cb_put(cb);
        nlmsg_free(msg);
        goto out;

nla_put_failure:
        fprintf(stderr, "failed to add attribute to netlink message\n");
out:    
        return ret;
}

/**
 * struct handler_args - arguments to resolve multicast group
 * @group: group name to resolve
 * @id:    ID it resolves into
 */
struct handler_args {
        const char      *group;
        int             id;
};


/* stolen from iw:genl.c */
static int family_handler(struct nl_msg *msg, void *arg)
{
        struct handler_args *grp = arg;
        struct nlattr *tb[CTRL_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *mcgrp;
        int rem_mcgrp;

        nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[CTRL_ATTR_MCAST_GROUPS])
                return NL_SKIP;

        nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
                struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

                nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
                          nla_data(mcgrp), nla_len(mcgrp), NULL);

                if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
                    !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
                        continue;
                if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                            grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
                        continue;
                grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
                break;
        }

        return NL_SKIP;
}

/* stolen from iw:genl.c */
int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group)
{
        struct nl_msg *msg;
        struct nl_cb *cb;
        int ret, ctrlid;
        struct handler_args grp = {
                .group = group,
                .id = -ENOENT,
        };

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb) {
                ret = -ENOMEM;
                goto out_fail_cb;
        }

        ctrlid = genl_ctrl_resolve(sock, "nlctrl");

        genlmsg_put(msg, 0, 0, ctrlid, 0,
                    0, CTRL_CMD_GETFAMILY, 0);

        ret = -ENOBUFS;
        NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

        ret = nl_send_auto_complete(sock, msg);
        if (ret < 0) 
                goto out;

        ret = 1;

        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, family_handler, &grp);

        while (ret > 0)
                nl_recvmsgs(sock, cb);

        if (ret == 0) 
                ret = grp.id;
nla_put_failure:
out:
        nl_cb_put(cb);
out_fail_cb:
        nlmsg_free(msg);
        return ret;
}

/**
 * Allocate a GeNetlink socket ready to listen for nl80211 multicast group @grp
 * @grp: identifier of an nl80211 multicast group (e.g. "scan")
 */
struct nl_sock *alloc_nl_mcast_sk(const char *grp)
{
        int mcid, ret;
        struct nl_sock *sk = nl_socket_alloc();

        if (!sk){
                fprintf(stderr, "failed to allocate netlink multicast socket");
		return NULL;
	}

        if (genl_connect(sk)){ 
                fprintf(stderr, "failed to connect multicast socket to GeNetlink");
		return NULL;
	}

        mcid = nl_get_multicast_id(sk, "nl80211", grp);
        if (mcid < 0){
                fprintf(stderr, "failed to resolve nl80211 '%s' multicast group", grp);
		return NULL;
	}

        ret = nl_socket_add_membership(sk, mcid);
        if (ret){
                fprintf(stderr, "failed to join nl80211 multicast group %s", grp);
		return NULL;
	}

        return sk;
}
