#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

#include "dnsasm_kernel.h"

/* Module information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antigravity");
MODULE_DESCRIPTION("DNS Netfilter Packet Driver for dnsscienced with RPZ");
MODULE_VERSION("0.2");

/* Constants */
#define DNS_PORT 53
#define MAX_DOMAIN_LEN 256
#define PROC_FILENAME "dns_firewall_rules"

/* RPZ Actions */
#define RPZ_ACTION_PASS 0
#define RPZ_ACTION_DROP 1
#define RPZ_ACTION_MARK 2

/* Parameters */
static bool debug_logging = true;
module_param(debug_logging, bool, 0644);
MODULE_PARM_DESC(debug_logging, "Enable debug logging");

/* --- Policy Storage (Hash Table) --- */

struct rpz_rule {
    char domain[MAX_DOMAIN_LEN];
    int action;
    u32 mark;
    struct hlist_node node;
    struct rcu_head rcu;
};

/* 10 bits = 1024 buckets */
static DEFINE_HASHTABLE(rpz_ht, 10);
static DEFINE_SPINLOCK(rpz_lock);

/* Compute simplified hash for domain string */
static u32 domain_hash(const char *str) {
    u32 hash = 0;
    while (*str) {
        hash = hash * 31 + *str;
        str++;
    }
    return hash;
}

static void free_rule_rcu(struct rcu_head *head) {
    struct rpz_rule *rule = container_of(head, struct rpz_rule, rcu);
    kfree(rule);
}

/* --- Packet Parsing Logic --- */

static int parse_dns_header(const u8 *packet, size_t len, dnsasm_header_t *out)
{
    if (len < DNS_HEADER_SIZE) {
        return DNSASM_ERR_SHORT;
    }
    out->id      = ntohs(*(const __be16 *)(packet + 0));
    out->flags   = ntohs(*(const __be16 *)(packet + 2));
    out->qdcount = ntohs(*(const __be16 *)(packet + 4));
    // We only care about id, flags, qdcount for now
    return DNSASM_OK;
}

/* 
 * Extracts QNAME from packet at offset.
 * Converts to "dot" format (example.com) and lowercases.
 * out_buffer must be MAX_DOMAIN_LEN.
 */
static int parse_qname(const u8 *packet, size_t len, size_t offset, char *out_buffer)
{
    size_t pos = offset;
    size_t out_pos = 0;
    
    while (pos < len) {
        u8 label_len = packet[pos];
        
        /* End of name */
        if (label_len == 0) {
            if (out_pos > 0) {
                out_buffer[out_pos - 1] = '\0'; /* Remove trailing dot */
            } else {
                out_buffer[0] = '\0'; /* Root */
            }
            return 0; /* Success */
        }
        
        /* Pointers not supported in simple QNAME parser yet */
        if ((label_len & 0xC0) == 0xC0) {
            return DNSASM_ERR_POINTER; 
        }
        
        if (pos + 1 + label_len > len) return DNSASM_ERR_SHORT;
        if (out_pos + label_len + 1 > MAX_DOMAIN_LEN) return DNSASM_ERR_OVERFLOW;
        
        /* Copy and lowercase */
        int i;
        for (i = 0; i < label_len; i++) {
            u8 c = packet[pos + 1 + i];
            if (c >= 'A' && c <= 'Z') c += 32;
            out_buffer[out_pos++] = c;
        }
        out_buffer[out_pos++] = '.';
        
        pos += 1 + label_len;
    }
    return DNSASM_ERR_SHORT;
}

/* --- Netfilter Hook --- */

static unsigned int dns_hook_func(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct udphdr _udph;
    u8 dns_header_buf[DNS_HEADER_SIZE];
    dnsasm_header_t dns_hdr;
    char qname[MAX_DOMAIN_LEN];
    struct rpz_rule *rule;
    int ret;
    u32 hash;
    
    // Safety checks
    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_UDP) return NF_ACCEPT;
    
    udph = skb_header_pointer(skb, iph->ihl * 4, sizeof(_udph), &_udph);
    if (!udph) return NF_ACCEPT;
    
    /* Standard DNS ports only */
    if (ntohs(udph->dest) != DNS_PORT && ntohs(udph->source) != DNS_PORT)
        return NF_ACCEPT;

    int data_offset = (iph->ihl * 4) + sizeof(struct udphdr);
    
    /* Read Header */
    if (skb_header_pointer(skb, data_offset, DNS_HEADER_SIZE, dns_header_buf) == NULL)
        return NF_ACCEPT;

    if (parse_dns_header(dns_header_buf, DNS_HEADER_SIZE, &dns_hdr) != DNSASM_OK)
        return NF_ACCEPT;

    /* Only inspect Queries (QR=0) or Responses with Questions?
     * Usually RPZ filters based on the Question.
     */
    if (dns_hdr.qdcount > 0) {
        /* Read QNAME. Max reasonable packet size check for simplicity */
        /* We need more data than just header. Let's pull up to 512 bytes safely */
        u8 buf[512];
        int read_len = skb->len - data_offset;
        if (read_len > sizeof(buf)) read_len = sizeof(buf);
        
        if (skb_header_pointer(skb, data_offset, read_len, buf) == NULL)
             return NF_ACCEPT; // Could not read
        
        /* Parse QNAME starting after header (offset 12) */
        if (parse_qname(buf, read_len, 12, qname) == 0) {
            
            /* RCU Lookup */
            rcu_read_lock();
            hash = domain_hash(qname);
            bool match = false;
            
            hash_for_each_possible_rcu(rpz_ht, rule, node, hash) {
                if (strcmp(rule->domain, qname) == 0) {
                    /* Match! */
                    match = true;
                    
                    if (debug_logging) {
                        printk(KERN_INFO "dns_firewall: RPZ MATCH %s Action=%d Mark=0x%x\n", 
                               qname, rule->action, rule->mark);
                    }
                    
                    if (rule->action == RPZ_ACTION_DROP) {
                        rcu_read_unlock();
                        return NF_DROP;
                    }
                    if (rule->action == RPZ_ACTION_MARK) {
                        skb->mark = rule->mark;
                    }
                    break; /* Found, done */
                }
            }
            rcu_read_unlock();
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops dns_ops[] = {
    {
        .hook     = dns_hook_func,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook     = dns_hook_func,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
    },
};

/* --- Procfs Management --- */

static int rpz_show(struct seq_file *m, void *v) {
    struct rpz_rule *rule;
    int bkt;

    rcu_read_lock();
    hash_for_each_rcu(rpz_ht, bkt, rule, node) {
        seq_printf(m, "%s ", rule->domain);
        if (rule->action == RPZ_ACTION_DROP) seq_puts(m, "DROP\n");
        else if (rule->action == RPZ_ACTION_MARK) seq_printf(m, "MARK 0x%x\n", rule->mark);
        else seq_puts(m, "PASS\n");
    }
    rcu_read_unlock();
    return 0;
}

static int rpz_open(struct inode *inode, struct file *file) {
    return single_open(file, rpz_show, NULL);
}

/* Command format: 
 * "+ domain DROP"
 * "+ domain MARK 0x123"
 * "- domain"
 */
static ssize_t rpz_write(struct file *file, const char __user *buffer,
                         size_t count, loff_t *pos) {
    char kbuf[128];
    char dom[MAX_DOMAIN_LEN];
    char action_str[16];
    char mark_str[16];
    struct rpz_rule *rule;
    u32 hash;
    int bkt;
    struct hlist_node *tmp;

    if (count > sizeof(kbuf) - 1) return -EINVAL;
    if (copy_from_user(kbuf, buffer, count)) return -EFAULT;
    kbuf[count] = '\0';
    
    /* Simple parsing */
    char op;
    if (sscanf(kbuf, "%c %255s %15s %15s", &op, dom, action_str, mark_str) < 2) {
        return -EINVAL;
    }

    if (op == '-') {
        /* Remove */
        spin_lock(&rpz_lock);
        hash = domain_hash(dom);
        hash_for_each_possible_safe(rpz_ht, rule, tmp, node, hash) {
            if (strcmp(rule->domain, dom) == 0) {
                hash_del_rcu(&rule->node);
                call_rcu(&rule->rcu, free_rule_rcu);
                break;
            }
        }
        spin_unlock(&rpz_lock);
    } 
    else if (op == '+') {
        /* Add */
        int act = RPZ_ACTION_PASS;
        u32 mk = 0;
        
        if (strcmp(action_str, "DROP") == 0) act = RPZ_ACTION_DROP;
        else if (strcmp(action_str, "MARK") == 0) {
            act = RPZ_ACTION_MARK;
            if (kstrtou32(mark_str, 16, &mk)) mk = 0;
        }

        struct rpz_rule *new_rule = kzalloc(sizeof(*new_rule), GFP_KERNEL);
        if (!new_rule) return -ENOMEM;
        
        strncpy(new_rule->domain, dom, MAX_DOMAIN_LEN);
        new_rule->action = act;
        new_rule->mark = mk;
        
        spin_lock(&rpz_lock);
        /* Check exist? Remove first to easy update */
        hash = domain_hash(dom);
         hash_for_each_possible_safe(rpz_ht, rule, tmp, node, hash) {
            if (strcmp(rule->domain, dom) == 0) {
                 hash_del_rcu(&rule->node);
                 call_rcu(&rule->rcu, free_rule_rcu);
            }
        }
        
        hash_add_rcu(rpz_ht, &new_rule->node, hash);
        spin_unlock(&rpz_lock);
    }
    
    return count;
}

static const struct proc_ops rpz_proc_ops = {
    .proc_open = rpz_open,
    .proc_read = seq_read,
    .proc_write = rpz_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* --- Module Management --- */

static int __init dns_firewall_init(void)
{
    int ret;
    printk(KERN_INFO "dns_firewall_rpz: loading...\n");
    
    /* Register Hooks */
    ret = nf_register_net_hooks(&init_net, dns_ops, ARRAY_SIZE(dns_ops));
    if (ret < 0) return ret;

    /* Create Proc entry */
    if (!proc_create(PROC_FILENAME, 0666, NULL, &rpz_proc_ops)) {
        nf_unregister_net_hooks(&init_net, dns_ops, ARRAY_SIZE(dns_ops));
        return -ENOMEM;
    }

    printk(KERN_INFO "dns_firewall_rpz: loaded. /proc/%s created.\n", PROC_FILENAME);
    return 0;
}

static void __exit dns_firewall_exit(void)
{
    struct rpz_rule *rule;
    int bkt;
    struct hlist_node *tmp;

    /* Cleanup Proc */
    remove_proc_entry(PROC_FILENAME, NULL);

    /* Unregister */
    nf_unregister_net_hooks(&init_net, dns_ops, ARRAY_SIZE(dns_ops));
    
    /* Cleanup Hash Table */
    /* No need to lock here as module is exiting, no one else accesses */
    hash_for_each_safe(rpz_ht, bkt, tmp, rule, node) {
        hash_del(&rule->node);
        kfree(rule);
    }
    
    printk(KERN_INFO "dns_firewall_rpz: unloaded\n");
}

module_init(dns_firewall_init);
module_exit(dns_firewall_exit);
