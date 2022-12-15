#include <linux/module.h>   // Needed by all modules
#include <linux/kernel.h>   // Needed for KERN_ALERT
#include <linux/init.h>     // Needed for the macros

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>

unsigned int hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    unsigned int src_port;
    struct iphdr* ip_header;

	ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT;
    }

    struct in_addr source_address;
    source_address.s_addr = ip_header->saddr;

    struct tcphdr* tcph = tcp_hdr(skb);
    src_port = ntohs(tcph->source);

    if (src_port == 80 || src_port == 443) {
        if (source_address.s_addr == in_aton("192.229.173.207")) { // D: Only block web traffic from a certain domain, e.g., google.com, and allow all other traffic
            printk(KERN_INFO "Firewall D -- Dropping TCP Packet from 192.299.173.207.\n");
            return NF_DROP;
        }
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
    printk(KERN_DEBUG "Firewall D Module loaded.\n");
    return 0;
}

static void firewall_exit(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_DEBUG "Firewall D Module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
