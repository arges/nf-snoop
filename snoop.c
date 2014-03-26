/*
 * Simple netfiler packet snooping module.
 *
 * (C) 2014 Canonical Ltd., Chris J Arges <christopherarges@gmail.com>
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define AUTHOR      "Chris J Arges <chris.j.arges@canonical.com>"
#define LICENSE     "GPL"

static struct nf_hook_ops hooks[NF_INET_NUMHOOKS];
static char *nf_hook_names[NF_INET_NUMHOOKS] = {
	"PRE_ROUTING ",
	"LOCAL_IN    ",
	"FORWARD     ",
	"LOCAL_OUT   ",
	"POST_ROUTING"
};

unsigned int snoop_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)( struct sk_buff * ) )
{
	struct iphdr *iph;
	if (!skb) return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (!iph) return NF_ACCEPT;

	/* skip lo packets */
	if (iph->saddr == iph->daddr) return NF_ACCEPT;

	/* print packet information */
	pr_debug( "%s: packet %p dev %s %pI4->%pI4\n", nf_hook_names[hooknum], skb, out->name,
		&(iph->saddr), &(iph->daddr));

	return NF_ACCEPT;
}

static int __init snoop_init(void)
{
	int i;
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		hooks[i].hook = snoop_hook;
		hooks[i].pf = PF_INET;
		hooks[i].hooknum = i;
		hooks[i].priority = i;
		nf_register_hook(&hooks[i]);
	}
	return 0;
}

static void __exit snoop_cleanup(void)
{
	int i;
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		nf_unregister_hook(&hooks[i]);
	}
}

module_init(snoop_init);
module_exit(snoop_cleanup);

MODULE_AUTHOR(AUTHOR);
MODULE_LICENSE(LICENSE);
