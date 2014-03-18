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

static struct nf_hook_ops out_hook;

unsigned int snoop_out_hook( unsigned int hooknum, struct sk_buff *skb,
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
	printk( "sent %p dev %s %pI4->%pI4\n", skb, in->name,
		&(iph->saddr), &(iph->daddr));

	return NF_ACCEPT;
}

static int __init snoop_init(void)
{
	out_hook.hook = snoop_out_hook;
	out_hook.pf = PF_INET;
	out_hook.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&out_hook);

	return 0;
}

static void __exit snoop_cleanup(void)
{
	nf_unregister_hook(&out_hook);
}

module_init(snoop_init);
module_exit(snoop_cleanup);

MODULE_AUTHOR(AUTHOR);
MODULE_LICENSE(LICENSE);
