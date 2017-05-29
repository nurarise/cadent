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
#include <net/ethernet.h>
#include <linux/wireless.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
* struct scan_result: scanning result information.
*
* freq:          frequency on which the given ssid is matched.
* bitrate:       bitrate calculated through rssi by radio
* linkq:         link quality in percentage.
* signallevel:   received signal level
* noiselevel:    noise level at receiver.
*/
struct scan_result {
        struct ether_addr       ap_addr;
        char                    essid[IW_ESSID_MAX_SIZE + 2];
        uint32_t                freq;
        int                     chan;
        uint8_t                 has_key:1;

        uint32_t                last_seen;
        uint64_t                tsf;

        int8_t                  bss_signal;
        uint8_t                 bss_signal_qual;
        uint16_t                bss_capa;
        uint8_t                 bss_sta_count,
                                bss_chan_usage;
}scan_result;


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
        struct nlmsg_attribute    *msg_args;
        uint8_t                 msg_args_len;
};

/*
* struct nl80211_ctx - netlink 802.11 context structure
* nlsock: netlink socket descriptor
* nl80211id: id for nl80211 interface
* nlmsglen: netlink message length.
* ifindex: wifi interface index
*/      
struct nl80211_ctx {    
        struct nl_sock  *nlsock;
        int              nl80211id;
        int              nlmsglen;
        uint32_t         ifindex;
};

int nlsocket_open(const char *ifname);
struct nl_sock *alloc_nl_mcast_sk(const char *grp);
int nl80211cmd_handle(struct nl80211_cmd *cmd);
void nlsocket_destroy(void);
#ifdef __cplusplus
}
#endif

#endif //ifndef __IW_CMD_H__
