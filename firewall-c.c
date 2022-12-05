#include <linux/module.h>   // Needed by all modules
#include <linux/kernel.h>   // Needed for KERN_ALERT
#include <linux/init.h>     // Needed for the macros

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

unsigned int hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) { // Handle TCP hdrs
        tcph = tcp_hdr(skb);
        int port = ntohs(tcph->dest);
        if (port == 80 || port == 443) { // A: Only block telnet traffic
            printk(KERN_INFO "Firewall C -- Accepting TCP packet\n");
            return NF_ACCEPT;
        }
	} else if (iph->protocol == IPPROTO_UDP) {
        printk(KERN_INFO "Firewall C -- UDP packet accepted for browser\n");
        return NF_ACCEPT;
    }
	return NF_DROP;
}

static struct nf_hook_ops nfho __read_mostly = {
        .pf = PF_INET, // Internet IP Protocol 
        .priority = NF_IP_PRI_FIRST,
        .hooknum = NF_INET_PRE_ROUTING, // capture right after packet is recieved
        .hook = (nf_hookfn *) hook
};

static int firewall_init(void) {
    nf_register_hook(&nfho);
    printk(KERN_DEBUG "Firewall C Module loaded.\n");
    return 0;
}

static void firewall_exit(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_DEBUG "Firewall C Module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
