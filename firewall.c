// for general purpose
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>

// unique for networking
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/spinlock.h>

//for real time updates
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define DROP NF_DROP
#define ACCEPT NF_ACCEPT
#define MAX_BLOCK_SIZE 100
#define MAX_URL_LENGTH 64

static struct nf_hook_ops hookstruct_in;
static struct nf_hook_ops hookstruct_out;

static u16 blocked_src_ports[MAX_BLOCK_SIZE];
static u16 blocked_destination_ports[MAX_BLOCK_SIZE];
static __be32 blocked_source_ips[MAX_BLOCK_SIZE];
static __be32 blocked_destination_ips[MAX_BLOCK_SIZE];
static char blocked_urls[MAX_BLOCK_SIZE][MAX_URL_LENGTH];

static int blocked_src_port_count = 0;
static int blocked_destination_port_count = 0;
static int blocked_source_ip_count = 0;
static int blocked_destination_ip_count = 0;
static int blocked_url_count = 0;


#define PROC_FILENAME "rules"

DEFINE_SPINLOCK(fw_lock);

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

//adds blocked ports to list from user input
static ssize_t rule_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos){
	char buf[256];
	char cmd[32];
	char val[64];

	int len = min(count, (size_t)(sizeof(buf)-1));

	if(copy_from_user(buf, ubuf, len)) return -EFAULT;
	buf[len] = '\0';

	if(sscanf(buf, "%31s %63s", cmd, val)==2){
		spin_lock_bh(&fw_lock);
		if(strcmp(cmd, "source_ip")==0 && blocked_source_ip_count< MAX_BLOCK_SIZE){
			blocked_source_ips[blocked_source_ip_count++] = in_aton(val);
			printk(KERN_INFO "Firewall added to source ip %s\n", val);
		}
		else if((strcmp(cmd, "destination_ip")==0 || strcmp(cmd, "website")==0)&& blocked_destination_ip_count<MAX_BLOCK_SIZE){
			blocked_destination_ips[blocked_destination_ip_count++] = in_aton(val);
			printk(KERN_INFO "Firewall added to destination ip %s \n", val);
		}
		else if(strcmp(cmd, "source_port") == 0 && blocked_src_port_count < MAX_BLOCK_SIZE){
			u16 port;
			if (kstrtou16(val, 10, &port) == 0){
			blocked_src_ports[blocked_src_port_count++] = port;
			printk(KERN_INFO "Firewall added to source port %d \n", port);
			}
		}
		else if ((strcmp(cmd, "dest_port") == 0||strcmp(cmd, "destination_port")==0) && blocked_destination_port_count < MAX_BLOCK_SIZE) {
            u16 port;
            if (kstrtou16(val, 10, &port) == 0){
			blocked_destination_ports[blocked_destination_port_count++] = port;
			printk(KERN_INFO "Firewall added to destination port %d\n", port);
			}
        }
		else if (strcmp(cmd,"block_url")==0 && blocked_url_count<MAX_BLOCK_SIZE){
			strncpy(blocked_urls[blocked_url_count], val, MAX_URL_LENGTH-1);
			blocked_urls[blocked_url_count][MAX_URL_LENGTH-1] = '\0';
			printk(KERN_INFO "Firewall added blocked URL %s\n", blocked_urls[blocked_url_count]);
			blocked_url_count++;
		}
		spin_unlock_bh(&fw_lock);
	}

	return count;
}

static const struct proc_ops fw_proc_ops = {
    .proc_write = rule_write,
};




//checks is ip adress or port number is blocked
static int is_sourceIP_blocked(__be32 ip){
	for(int i=0; i<blocked_source_ip_count; i++){
		if(blocked_source_ips[i]==ip) return 1;
	}
	return 0;
}

static int is_destinationIP_blocked(__be32 ip){
	for(int i=0; i<blocked_destination_ip_count; i++){
		if(blocked_destination_ips[i]==ip) return 1;
	}
	return 0;
}

static int is_src_port_blocked(u16 port){
	for(int i=0; i<blocked_src_port_count; i++){
		if(blocked_src_ports[i]==port) return 1;
	}
	return 0;
}

static int is_destination_port_blocked(u16 port){
	for(int i=0; i<blocked_destination_port_count; i++){
		if(blocked_destination_ports[i]==port) return 1;
	}
	return 0;
}

//to check if DNS contains any blocked website
//to see if its not DNS, we will check if its not UDP and not in port 53. If not DNS, we'll let it pass
static int is_website_blocked(struct sk_buff *skb){
	if(ip_hdr(skb)->protocol != IPPROTO_UDP) return 0;
	struct udphdr *udpheader = udp_hdr(skb);
	
	if(ntohs(udpheader->dest)!=53&& ntohs(udpheader->source)!=53) return 0;

	unsigned char *data = (unsigned char*)(((unsigned char *)udpheader + sizeof(struct udphdr)));
	int data_len = ntohs(udpheader->len) - sizeof(struct udphdr);

	if(data_len <=0) return 0; //alowing empty packet to passs through

	for(int i=0; i<blocked_url_count; i++){
		if(strnstr(data, blocked_urls[i], data_len)){
			return 1;
		}
	}

	return 0;
}




//main function
static unsigned int  block_handler(void* priv, struct sk_buff *skb, const struct nf_hook_state *state)
{


	if(!skb) return ACCEPT; //if package ahs nothing just accept it
	struct iphdr *ipheader=ip_hdr(skb);

	if(ipheader==NULL){
		printk(KERN_WARNING "No Ip adress found \n");
		return ACCEPT; 
		
	}

	__be32 src_ipadress = ipheader->saddr;
	__be32 destination_ipadress = ipheader->daddr;

	u16 src_port=0, destination_port = 0; 
	bool has_port =false;

	if(ipheader->protocol == IPPROTO_UDP){ //checking if udp header is accessible
		struct udphdr *udpheader = udp_hdr(skb);
		 
		src_port = ntohs(udpheader->source);
		destination_port = ntohs(udpheader->dest);
		has_port = true;
	}
	else if(ipheader->protocol == IPPROTO_TCP){ //checking if ipheader is accessible
		struct tcphdr *tcpheader = tcp_hdr(skb);

		src_port = ntohs(tcpheader->source);
		destination_port = ntohs(tcpheader->dest);
		has_port = true;

	}

	// Lock the arrays to them against the packet to prevent race conditions
	unsigned int action = ACCEPT;
    spin_lock_bh(&fw_lock);

	if(is_sourceIP_blocked(src_ipadress)){
		printk(KERN_INFO "Dropped: src=%pI4 \n", &src_ipadress);
		action = DROP;
	}

	else if(is_destinationIP_blocked(destination_ipadress)){
		printk(KERN_INFO " Dropped: destination=%pI4 \n", &destination_ipadress);
		action = DROP;
	}

	else if(is_website_blocked(skb)){
		printk(KERN_INFO "Dropped: website. ");
		action = DROP;

	}

	else if(has_port){
		if(is_src_port_blocked(src_port)){
			printk(KERN_INFO " Dropped SRC Port match: %d\n", src_port);
			action = DROP;
		}
		if(is_destination_port_blocked(destination_port)){
			printk(KERN_INFO " Dropped destination Port match: %d\n", destination_port);
			action =  DROP;			
		}	
	}
	spin_unlock_bh(&fw_lock);

	return action;

}



//compulsary programs for when a module is entered into the kernel (insmod)
static int __init firewall_initialization(void)
{
	//creating hook for PRE_ROUTING (Input side)	
	hookstruct_in.hook = block_handler;
	hookstruct_in.hooknum = NF_INET_PRE_ROUTING;
	hookstruct_in.pf = NFPROTO_IPV4;
	hookstruct_in.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook (&init_net, &hookstruct_in);


	//registering hook for POST_ROUTING (output side)
	hookstruct_out.hook=block_handler;
	hookstruct_out.hooknum = NF_INET_POST_ROUTING;
	hookstruct_out.pf = NFPROTO_IPV4;
	hookstruct_out.priority = NF_IP_PRI_FIRST;

	nf_register_net_hook (&init_net, &hookstruct_out);

	proc_dir = proc_mkdir("my_firewall", NULL);
	if (!proc_dir) {
        printk(KERN_ERR "Failed to create /proc/my_firewall\n");
        return -ENOMEM;
    }

	proc_file = proc_create(PROC_FILENAME, 0666, proc_dir, &fw_proc_ops);
	if(!proc_file){
		printk(KERN_ERR "Failed to create the rules file\n");
		remove_proc_entry("my_firewall", NULL);
	}

	printk(KERN_INFO "Firewall program has started\n");
	printk(KERN_INFO "Interface at /proc/my_firewall/rules\n");
	return 0;
}


//compulsary program for when module is removed from kernel( rmmod)
static void  __exit firewall_exit(void)
{
	nf_unregister_net_hook(&init_net, &hookstruct_in);
	nf_unregister_net_hook(&init_net, &hookstruct_out);

	remove_proc_entry("rules", proc_dir);
    remove_proc_entry("my_firewall", NULL);


	printk(KERN_INFO "Exiting firewall program\n");
}

module_init(firewall_initialization);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
