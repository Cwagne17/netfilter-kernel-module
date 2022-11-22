#include <linux/module.h>   // Needed by all modules
#include <linux/kernel.h>   // Needed for KERN_ALERT
#include <linux/init.h>     // Needed for the macros

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

unsigned int hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    printk(KERN_DEBUG "Hooked yay!\n");
    // A: Only block telnet traffic
    // B: Only block UDP packages on port > 2500
    // C: Only allow web traffic
    // D: Only block web traffic from a certain domain, e.g., google.com, and allow all other traffic
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
    printk(KERN_DEBUG "Firewall Module loaded.\n");
    return 0;
}

static void firewall_exit(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_DEBUG "Firewall Module unloaded.\n");
}

module_init(firewall_init);
module_exit(firewall_exit);
