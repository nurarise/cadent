#ifndef __IW_CMD_H__
#define __IW_CMD_H__

#include <stdio.h>
#include <stdint.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
* struct scaninfo: structure for scanning information.
*
* freq:          frequency on which the given ssid is matched.
* bitrate:       bitrate calculated through rssi by radio
* linkq:         link quality in percentage.
* signallevel:   received signal level
* noiselevel:    noise level at receiver.
*/
struct scan_info {
        uint32_t        freq;
        uint32_t        bitrate;
        uint32_t        linkq;
        uint32_t        signallevel;
        uint32_t        noiselevel;
}scan_info;

/*
*
* struct nl80211_cmd - inspired from iw:iw.h & wavemon
* nlcmd:        nl80211 command to send via GeNetlink
* handler:      netlink callback handler
* handler_arg:  argument for @handler
* flags:         flags to set in the GeNetlink message
*/
struct nl80211_cmd {
        enum nl80211_commands    nlcmd;
        int (*nl_handler)(struct nl_msg *msg, void *arg);
        void                    *handler_arg;
        int                      flags;
};

/*
* struct nl80211_ctx - 
*
*
*/
struct nl80211_ctx {
        struct nl_sock  *nlsock;
        int             nl80211id;
        int             nlmsglen;
	uint32_t	ifindex;
};

int nlsocket_open(const char *ifname);
int nl80211cmd_handle(struct nl80211_cmd *cmd);
void nlsocket_destroy(void);
#ifdef __cplusplus
}
#endif

#endif //ifndef __IW_CMD_H__
