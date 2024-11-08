#include <string.h>
#include "queue.h"
#include <stdbool.h>
#include "lib.h"
#include <arpa/inet.h>
#include "protocols.h"

/* Funny name, didn't know what to call this */
#define MAX_BINARY_SEARCH_LINEAR_TRAVERSAL 100
#define MAX_TABLE_SIZE 80000
#define ETHERTYPE_IP 0x0800 /* IP protocol */
#define STATIC_MAC_TABLE "arp_table.txt"
#define MAC_ADDRESS_BYTES_LENGTH 6

#define DESTINATION_UNREACHABLE_TYPE 3
#define DESTINATION_UNREACHABLE_CODE 0
#define TIME_EXCEEDED_TYPE 11
#define TIME_EXCEEDED_CODE 0
#define ECHO_REQUEST_TYPE 8
#define ECHO_REQUEST_CODE 0
#define ECHO_REPLY_TYPE 0
#define ECHO_REPLY_CODE 0

#define MAX_TTL 64
/* see https://www.rfc-editor.org/rfc/rfc792  | page 1*/
#define ICMP_PROTOCOL_ID 1
#define ICMP_TOTAL_LEN sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8

/* Descending order comparator for the route table,
 * all entries will be sorted first by their prefix value
 * if two entries have the same prefix value, I'll compare
 * the value of their masks becaues the best match would be 
 * the one with the highest mask since it would generate the 
 * longest prefix (more details in README)
 */
int rtable_comparator(const void *o1, const void *o2) {
	struct route_table_entry *e1 = (struct route_table_entry *)o1;
	struct route_table_entry *e2 = (struct route_table_entry *)o2;

	return (e1->prefix == e2->prefix) ? (e2->mask - e1->mask) : (e2->prefix - e1->prefix);
}

struct arp_table_entry *mtable;
struct route_table_entry *rtable;
int rtable_size;
int mtable_size;

struct route_table_entry *get_best_entry(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_size) {
	int low = 0;
	int high = rtable_size - 1;
	struct route_table_entry *ret = NULL;

	while(1) {
		/* Avoids overflow */
		int mid = ((high - low) / 2) + low;
		struct route_table_entry rentry = rtable[mid];
		int common_prefix = (dest_ip & rentry.mask);

		if (common_prefix == rentry.prefix) {
			/* Might not be the longest possible prefix possible because of
			   mask length differences, as we've sorted in descending way, we'll
			   search higher in the table (on the negedge of the indexes)
			   to find a longer match, up until the the rtable_ttl reaches 0 */
			ret = &rtable[mid];
			int rtable_ttl = MAX_BINARY_SEARCH_LINEAR_TRAVERSAL;
			while (rtable_ttl > 0 && mid >= 0) {
				mid--;
				if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix) {
					ret = &rtable[mid];
					continue;
				}
				rtable_ttl--;
			}
			break;
		} else if (common_prefix < rentry.prefix) {
			low = mid + 1;
		} else if (common_prefix > rentry.prefix) {
			high = mid - 1;
		}
		if (low > high) break;
	}
	return ret;
}

char *ip_to_string(uint32_t ip) {
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	return inet_ntoa(ip_addr);
}

char *mac_to_string(uint8_t *mac) {
	char *mac_string = malloc(20 *sizeof(char));
	sprintf (mac_string, "%02x%02x%02x%02x%02x%02x",
    mac[0], mac[1], mac[2],
	mac[3], mac[4], mac[5]);
	return mac_string;
}

void get_dest_mac_from_static_arp(struct arp_table_entry *mtable, int mtable_size,
								struct route_table_entry *rt_match, uint8_t *new_eth_d) {
	uint32_t dest_ip = rt_match->next_hop;
	for (int i = 0; i < mtable_size; i++) {
		if (mtable[i].ip == dest_ip)
			memcpy(new_eth_d, mtable[i].mac, MAC_ADDRESS_BYTES_LENGTH * sizeof(uint8_t));
	}
}
void send_icmp_time_exceeded(struct iphdr *old_ip_hdr, int interface) {
	char *new_packet = calloc(MAX_PACKET_LEN, sizeof(char));
	int new_len = ICMP_TOTAL_LEN;
	struct ether_header *new_ether_hdr = (struct ether_header *)new_packet;
	struct iphdr *new_ip_hdr = (struct iphdr *)(new_packet + sizeof(struct ether_header));
	struct icmphdr *new_icmp_hdr = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	new_ether_hdr->ether_type = htons(ETHERTYPE_IP);

	new_icmp_hdr->code = TIME_EXCEEDED_CODE;
	new_icmp_hdr->type = TIME_EXCEEDED_TYPE;
	new_icmp_hdr->checksum = htons(checksum((u_int16_t*) new_icmp_hdr, sizeof (struct icmphdr)));

	new_ip_hdr->tos = 0;
	new_ip_hdr->frag_off = 0;
	new_ip_hdr->version = 4;
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr->protocol = ICMP_PROTOCOL_ID;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->id = 1;
	new_ip_hdr->ttl = MAX_TTL;
	new_ip_hdr->daddr = old_ip_hdr->saddr;
	new_ip_hdr->saddr = old_ip_hdr->daddr;
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));
	memcpy(new_icmp_hdr + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr) + 8);
	/* Route is guaranteed to exist since we received a package from it,
	   so no need for sanity checks, at least in this homework's context i guess */
	struct route_table_entry *rt_match = get_best_entry(new_ip_hdr->daddr, rtable, rtable_size);
	get_dest_mac_from_static_arp(mtable, mtable_size, rt_match, new_ether_hdr->ether_dhost);
	get_interface_mac(interface, new_ether_hdr->ether_shost);
	printf("Sending ICMP TIME EXCEEDED packet to interface: %d, to MAC address: %s with destination ip: %s\n",
			rt_match->interface, mac_to_string(new_ether_hdr->ether_dhost), ip_to_string(rt_match->next_hop));

	send_to_link(rt_match->interface, new_packet, new_len);
}

void send_icmp_destination_unreachable(struct iphdr *old_ip_hdr, int interface) {
	char *new_packet = calloc(MAX_PACKET_LEN, sizeof(char));
	int new_len = ICMP_TOTAL_LEN;
	struct ether_header *new_ether_hdr = (struct ether_header *)new_packet;
	struct iphdr *new_ip_hdr = (struct iphdr *)(new_packet + sizeof(struct ether_header));
	struct icmphdr *new_icmp_hdr = (struct icmphdr *)(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	new_ether_hdr->ether_type = htons(ETHERTYPE_IP);

	new_icmp_hdr->type = DESTINATION_UNREACHABLE_TYPE;
	new_icmp_hdr->code = DESTINATION_UNREACHABLE_CODE;
	new_icmp_hdr->checksum = htons(checksum((u_int16_t*) new_icmp_hdr, sizeof (struct icmphdr)));

	new_ip_hdr->tos = 0;
	new_ip_hdr->frag_off = 0;
	new_ip_hdr->version = 4;
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr->protocol = ICMP_PROTOCOL_ID;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->id = 1;
	new_ip_hdr->ttl = MAX_TTL;
	new_ip_hdr->daddr = old_ip_hdr->saddr;
	new_ip_hdr->saddr = old_ip_hdr->daddr;
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));
	memcpy(new_icmp_hdr + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr) + 8);
	/* Route is guaranteed to exist since we received a package from it,
	   so no need for sanity checks, at least in this homework's context i guess */
	struct route_table_entry *rt_match = get_best_entry(new_ip_hdr->daddr, rtable, rtable_size);
	get_dest_mac_from_static_arp(mtable, mtable_size, rt_match, new_ether_hdr->ether_dhost);
	get_interface_mac(interface, new_ether_hdr->ether_shost);
	printf("Sending ICMP HOST UNREACHABLE packet to interface: %d, to MAC address: %s with destination ip: %s\n",
			rt_match->interface, mac_to_string(new_ether_hdr->ether_dhost), ip_to_string(rt_match->next_hop));

	send_to_link(rt_match->interface, new_packet, new_len);
}

/* Converts a dotted(string) representation of an IPv4 address to the
 * decimal notation then compares it the destination ip address stored
 * in the ip header and returns comparison result
 * https://stackoverflow.com/questions/5328070/how-to-convert-string-to-ip-address-and-vice-versa
 **/

bool packet_for_me(struct iphdr *ip_hdr, int interface) {
	struct sockaddr_in sa;
	inet_pton(AF_INET, get_interface_ip(interface), &(sa.sin_addr));
	if (ip_hdr->daddr == sa.sin_addr.s_addr) return true;
	return false;
}

void send_echo_reply(struct iphdr *ip_hdr, int interface, int len) {
	struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip_hdr + sizeof(struct iphdr));
	struct ether_header *eth_hdr = (struct ether_header *)((char *)(icmp_hdr)
							- sizeof(struct iphdr) - sizeof(struct ether_header));
	icmp_hdr->code = ECHO_REPLY_CODE;
	icmp_hdr->type = ECHO_REPLY_TYPE;
	/* Again, route existence is practically guaranteed in the context of this homework, so
	 * no sanity checks */
	struct route_table_entry *rt_match = get_best_entry(ip_hdr->saddr, rtable, rtable_size);
	uint32_t tmp = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = tmp;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct iphdr)));
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
	get_dest_mac_from_static_arp(mtable, mtable_size, rt_match, eth_hdr->ether_dhost);
	get_interface_mac(interface, eth_hdr->ether_shost);
	printf("Sending ECHO REPLY packet to interface: %d, to MAC address: %s with destination ip: %s\n",
			rt_match->interface, mac_to_string(eth_hdr->ether_dhost), ip_to_string(rt_match->next_hop));
	send_to_link(rt_match->interface, (char *)eth_hdr, len);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	char *rtable_filename = argv[1];
	
	rtable = malloc(sizeof(struct route_table_entry) * MAX_TABLE_SIZE);
	DIE(!rtable, "rtable malloc\n");
	mtable = malloc(sizeof(struct arp_table_entry) * MAX_TABLE_SIZE);
	DIE(!mtable, "mtable malloc\n");
	rtable_size = read_rtable(rtable_filename, rtable);
	mtable_size = parse_arp_table(STATIC_MAC_TABLE, mtable);
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), rtable_comparator);
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(packet, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)packet;
		uint8_t *interface_mac = malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, interface_mac);
		char *interface_mac_string = mac_to_string(interface_mac);
		printf("Received form interface: %d with IP address: %s and MAC : %s\n", interface,
				get_interface_ip(interface), interface_mac_string);

		if (eth_hdr->ether_type == htons(ETHERTYPE_IP)) {
			printf("Packet type: IPv4\n");
			struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
			
			/* Verify checksum */
			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = 0; /* Need to set to 0 before calculating new checksum value */
			uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			/* Both checksums are in network order, so comparison is valid */
			if (old_checksum != new_checksum){
				printf("Wrong checksum!\n");
				continue;
			}

			/* Verify TTL */
			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
				printf("TTL <= 1, building, ICMP TIME EXCEEDED package\n");
				send_icmp_time_exceeded(ip_hdr, interface);
				continue;
			} else { /* Decrement TTL and update the checksum */
				ip_hdr->ttl--;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			}
			/* Send echo reply if needed and move to the next packet */
			if (packet_for_me(ip_hdr, interface)) {
				printf("Packet's destination is myself!\n");
				if (((struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr)))->code 
					== ECHO_REQUEST_CODE
				&&  ((struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr)))->type
					== ECHO_REQUEST_TYPE) {
					printf("Received ICMP ECHO REQUEST, building ICMP ECHO REPLY packet!\n");
					send_echo_reply(ip_hdr, interface, len);
				}
				continue;
			}
			/* Calculate next hop and send packet on its way. Bye-Bye! */
			struct route_table_entry *rt_match = get_best_entry(ip_hdr->daddr, rtable, rtable_size);
			if (!rt_match) {
				printf("Route table match not found, sending ICMP DESTINATION UNREACHABLE packet!\n");
				/* Send packet on the same interface that it was received */
				send_icmp_destination_unreachable(ip_hdr, interface);
				continue;
			}

			uint8_t new_eth_d[6] = {0};
			get_dest_mac_from_static_arp(mtable, mtable_size, rt_match, new_eth_d);
			uint8_t empty_mac[MAC_ADDRESS_BYTES_LENGTH] = {0};
			if (memcmp(new_eth_d, empty_mac, MAC_ADDRESS_BYTES_LENGTH * sizeof(uint8_t)) == 0) {
				printf("MAC destination not found!\n");
				continue;
			}

			/* Router's interface MAC address = new eth packet source address */
			get_interface_mac(interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, new_eth_d, MAC_ADDRESS_BYTES_LENGTH * sizeof(uint8_t));

			
			printf("Sending IPv4 packet to interface: %d, to MAC address: %s with destination ip: %s\n",
					rt_match->interface, mac_to_string(eth_hdr->ether_dhost), ip_to_string(rt_match->next_hop));

			send_to_link(rt_match->interface, packet, len);
		}
	}
}

