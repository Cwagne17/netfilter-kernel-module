#include <linux/module.h>   // Needed by all modules
#include <linux/kernel.h>   // Needed for KERN_ALERT
#include <linux/init.h>     // Needed for the macros

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops nfho __read_mostly = {
        .pf = PF_INET, // Internet IP Protocol 
        .priority = NF_IP_PRI_FIRST,
        .hooknum = NF_INET_PRE_ROUTING, // capture right after packet is recieved
        .hook = (nf_hookfn *) nf_hook
};

unsigned int nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
	struct udphdr *udph;
    struct tcphdr *tcph;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
        else if (ntohs(tcp->dest) == 80 || ntohs(tcp->dest) == 443) {
            char saddr[16];
            snprintf(saddr, 16, "%pI4", &iph->saddr);
            if (strscmp(saddr, "8.8.8.8", 16) == 0) { // D: Only block web traffic from a certain domain, e.g., google.com, and allow all other traffic
                return NF_DROP;
            }
        }
	}
	return NF_ACCEPT;
}

static int firewall_init(void) {
    nf_register_hook(&nfho);
    printk(KERN_DEBUG "Firewall D Module loaded.\n");
    return 0;
}

static void firewall_exit(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_DEBUG "Firewall D Module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
