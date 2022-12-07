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
	struct udphdr *udph;

	iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_UDP) {
        return NF_ACCEPT;
    }
  
    udph = udp_hdr(skb);
  
    if (ntohs(udph->dest) > 2500) { // B: Only block UDP packages on port > 2500
        printk(KERN_INFO "Firewall B -- Dropping UDP packet\n");
        return NF_DROP;
    }

	return NF_ACCEPT;
}

static struct nf_hook_ops nfho __read_mostly = {
        .pf = PF_INET, // Internet IP Protocol 
        .priority = NF_IP_PRI_FIRST,
        .hooknum = NF_INET_PRE_ROUTING, // capture right after packet is recieved
        .hook = (nf_hookfn *) hook
};

static int firewall_init(void) {
    nf_register_hook(&nfho);
    printk(KERN_DEBUG "Firewall B Module loaded.\n");
    return 0;
}

static void firewall_exit(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_DEBUG "Firewall B Module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
