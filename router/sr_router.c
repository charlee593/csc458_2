/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    /* Check for minimum frame size */
    if (len < sizeof(struct sr_ethernet_hdr))
    {
        printf("---->> Received ethernet frame that is too short. <----\n");
        return;
    }

    printf("---->> Received packet of length %d <----\n", len);

    struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
    struct sr_if* iface = sr_get_interface(sr, interface);

    printf("---->> Interface %s <----\n", interface);

    /* Check if Ethertype is ARP */
    if (e_hdr->ether_type == htons(ethertype_arp))
    {
        /* Get the ARP header */
        struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

        printf("---->> Packet type ARP %u, %u <----\n",(unsigned)htons(e_hdr->ether_type), (unsigned)e_hdr->ether_type);
        printf("---->> An ARP packet protocol type %u, %u <----\n", arp_hdr->ar_pro, htons(arp_hdr->ar_pro));

        /* ARP request to me */
        if(arp_hdr->ar_op == htons(arp_op_request))
        {
            reply_to_arp_req(sr, e_hdr, arp_hdr, iface);
        }
        /* ARP reply */
        else if(arp_hdr->ar_op == htons(arp_op_reply))
        {
            process_arp_reply(sr, arp_hdr, iface);
        }
        else
        {
            printf("---->> Received ARP Packet that is neither reply nor request <----\n");
        }
    }
    /* Check if Ethertype is IP */
    else if (e_hdr->ether_type == htons(ethertype_ip))
    {
        printf("---->> Packet type IP <----\n");
        struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));

        /* Check for minimum total length of IP header */
        if(ip_hdr->ip_hl < IP_IHL)
        {
            printf("---->> IP header is smaller than the minimum size allowed <----\n");
            return;
        }

        /* Check packet checksum */
        uint16_t ip_checksum_temp = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        if(ip_checksum_temp != cksum(ip_hdr, sizeof(struct sr_ip_hdr)))
        {
            printf("---->> IP header checksum is incorrect %u <----\n", cksum(ip_hdr, sizeof(struct sr_ip_hdr)));
            return;
        }
        ip_hdr->ip_sum = ip_checksum_temp;


        /* Check if it is for me - find interfaces name */
        struct sr_if* curr_if = sr->if_list;
        while(curr_if != NULL)
        {
            if (ip_hdr->ip_dst == curr_if->ip)
            {
                printf("---->> Received IP packet for me <----\n");

                handle_ip_packet_for_router(sr, packet, len, ip_hdr, iface);

                return;
            }
            curr_if = curr_if->next;
        }

        /* It is not for me */
        if(curr_if == NULL)
        {
            printf("---->> It's not for me <----\n");

            handle_ip_packet_to_forward(sr, packet, len, ip_hdr, iface);
        }
    }
    else
    {
        printf("---->> Received Ethernet frame that contains neither IP packet nor ARP packet <----\n");
    }
} /* end sr_handlepacket */

/*
 * Method to send an ARP reply back to the sender
 * that sent an ARP request.
 */
void reply_to_arp_req(struct sr_instance* sr, struct sr_ethernet_hdr* e_hdr, struct sr_arp_hdr* arp_hdr, struct sr_if* iface)
{
    /* Construct an ARP reply and send it back */
    struct sr_ethernet_hdr* reply_packet_eth_hdr = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
    struct sr_arp_hdr* reply_packet_arp_hdr = ((struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr)));

    /* Ethernet header - Destination Address */
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_eth_hdr->ether_dhost[i] = e_hdr->ether_shost[i];

    /* Ethernet header - Source Address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_eth_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

    /* Ethernet header - Type */
    reply_packet_eth_hdr->ether_type = htons(ethertype_arp);


    /* ARP header - Hardware type */
    reply_packet_arp_hdr->ar_hrd = arp_hdr->ar_hrd;

    /* ARP header - Protocol type */
    reply_packet_arp_hdr->ar_pro = arp_hdr->ar_pro;

    /* ARP header - Hardware address length */
    reply_packet_arp_hdr->ar_hln = arp_hdr->ar_hln;

    /* ARP header - Protocol address length */
    reply_packet_arp_hdr->ar_pln = arp_hdr->ar_pln;

    /* ARP header - Opcode */
    reply_packet_arp_hdr->ar_op = htons(arp_op_reply);

    /* ARP header - Source hardware address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_arp_hdr->ar_sha[i] = iface->addr[i];

    /* ARP header - Source protocol address */
    reply_packet_arp_hdr->ar_sip = iface->ip;

    /* ARP header - Destination hardware address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_packet_arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];

    /* ARP header - Destination protocol address */
    reply_packet_arp_hdr->ar_tip = arp_hdr->ar_sip;

    /* Create packet */
    uint8_t* reply_packet = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)));
    memcpy(reply_packet, reply_packet_eth_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(reply_packet + sizeof(struct sr_ethernet_hdr), reply_packet_arp_hdr, sizeof(struct sr_arp_hdr));

    /* Send packet */
    sr_send_packet(sr, reply_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), iface->name);

    free(reply_packet_eth_hdr);
    free(reply_packet_arp_hdr);
    free(reply_packet);
} /* end reply_to_arp_req */

/*
 * Method to process the ARP reply that was received.
 * It put's the new IP to MAC mapping into the cache and sends
 * all outstanding packets waiting for this ARP reply.
 */
void process_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arp_hdr, struct sr_if* iface)
{
    /* When servicing an arp reply that gives us an IP->MAC mapping
       req = arpcache_insert(mac, ip)

    if req:
    send all packets on the req->packets linked list
    arpreq_destroy(req) */
    struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if(req)
    {
        struct sr_packet* curr_packet_to_send = req->packets;

        printf("---->> ARP Reply send outstanding packet <----\n");
        while(curr_packet_to_send != NULL)
        {
            struct sr_ethernet_hdr* curr_e_hdr = (struct sr_ethernet_hdr*)curr_packet_to_send->buf;

            /* Ethernet header - Destination Address */
            int i;
            for(i = 0; i < ETHER_ADDR_LEN; i++)
                curr_e_hdr->ether_dhost[i] = arp_hdr->ar_sha[i];

            /* Ethernet header - Source Address */
            for(i = 0; i < ETHER_ADDR_LEN; i++)
                curr_e_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

            /* Send packet */
            sr_send_packet(sr, curr_packet_to_send->buf, curr_packet_to_send->len, iface->name);

            curr_packet_to_send = curr_packet_to_send->next;
        }
        sr_arpreq_destroy(&sr->cache, req);
    }
}

/*
 * Method to deal with IP packets that are meant for one of the router's
 * interfaces. These may include ICMP, TCP or UDP payload.
 */
void handle_ip_packet_for_router(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_ip_hdr* ip_hdr, struct sr_if* iface)
{
    /* Received ICMP packet */
    if(ip_hdr->ip_p == ip_protocol_icmp)
    {
        struct sr_icmp_t0_hdr* icmp_hdr = (struct sr_icmp_t0_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
        /* Check ICMP packet checksum */
        uint16_t icmp_sum_temp = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        int icmp_len = ntohs(ip_hdr->ip_len) - IP_IHL_BYTES;
        if(icmp_sum_temp != cksum(icmp_hdr, icmp_len))
        {
            printf("---->> Incorrect checksum of ICMP packet %u <----\n", cksum(icmp_hdr, icmp_len));
            return;
        }
        icmp_hdr->icmp_sum = icmp_sum_temp;

        /* Received Echo request */
        if(icmp_hdr->icmp_type == icmp_type_echo_req)
        {
            /* Check minimum total length of the IP packet */
            if(ntohs(ip_hdr->ip_len) < (4 * ip_hdr->ip_hl + ICMP_ECHO_HDR_SIZE))
            {
                printf("---->> Total length of IP packet is too small for an echo request <----\n");
                return;
            }

            /* Send Echo reply */
            send_echo_reply(sr, packet, iface->name);
        }
        return;
    }

    /* Received ICMP packet UDP or TCP */
    if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
    {
        /* Send ICMP port unreachable */
        send_icmp_t3_or_t11(sr, packet, iface->name, icmp_type_dest_unreachable, icmp_code_port_unreachable);
    }
}

/*
 * Method to handle the case when the router receives an IP packet
 * with destination other than any of the router's interfaces.
 * So these packets need to be forwarded and any error cases
 * must be handled.
 */
void handle_ip_packet_to_forward(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_ip_hdr* ip_hdr, struct sr_if* iface)
{
    if(ip_hdr->ip_ttl <= 1)
    {
        printf("---->> Send ICMP (type 11, code 0) <----\n");
        send_icmp_t3_or_t11(sr, packet, iface->name, icmp_type_time_exceeded, 0);
        return;
    }

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

    /* Forward packet */
    struct sr_if* match_iface = lpm(sr, ip_hdr->ip_dst);
    if(!match_iface)
    {
        /* Send Destination net unreachable */
        send_icmp_t3_or_t11(sr, packet, iface->name, icmp_type_dest_unreachable, icmp_code_net_unreachable);
        return;
    }

    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    if(entry)
    {
        printf("---->> Found mac add in cache, forward packet <----\n");

        /* Forward packet */

        struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;

        /* Swap ethernet address */
        memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        /* Ethernet header - Source Address */
        memcpy(e_hdr->ether_shost, match_iface->addr, ETHER_ADDR_LEN);
        /* Send packet */
        sr_send_packet(sr, packet, len, match_iface->name);

        free(entry);
    }
    else
    {
        /* Put the ARP request into the queue and handle the new request */
        struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, iface->name);
        handle_arpreq(req, sr);
    }
}

/*
 * Method to send an echo reply back to the sender.
 */
void send_echo_reply(struct sr_instance* sr, uint8_t* received_frame, char* from_interface)
{
    struct sr_ethernet_hdr* received_eth_hdr = (struct sr_ethernet_hdr*)received_frame;
    struct sr_ip_hdr* received_ip_hdr = (struct sr_ip_hdr*)(received_frame + sizeof(struct sr_ethernet_hdr));
    struct sr_icmp_t0_hdr* received_icmp_hdr = (struct sr_icmp_t0_hdr*)(received_frame + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

    struct sr_ethernet_hdr* reply_eth_hdr = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
    struct sr_ip_hdr* reply_ip_hdr = ((struct sr_ip_hdr*)malloc(sizeof(struct sr_ip_hdr)));
    struct sr_icmp_t0_hdr* reply_icmp_hdr = ((struct sr_icmp_t0_hdr*)malloc(sizeof(struct sr_icmp_t0_hdr)));
    struct sr_if* iface = sr_get_interface(sr, from_interface);

    /* Ethernet destination address */
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_eth_hdr->ether_dhost[i] = received_eth_hdr->ether_shost[i];

    /* Ethernet source address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_eth_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

    /* Ethernet header - Type */
    reply_eth_hdr->ether_type = htons(ethertype_ip);

    /* IP header - ihl */
    reply_ip_hdr->ip_v = IPv4_VERSION;

    /* IP header - version */
    reply_ip_hdr->ip_hl = IP_IHL;

    /* IP header - Differentiated services */
    reply_ip_hdr->ip_tos = 0;

    /* IP header - total length */
    reply_ip_hdr->ip_len = received_ip_hdr->ip_len;

    /* IP header - identification */
    reply_ip_hdr->ip_id = IP_ID;

    /* IP header - fragment offset field */
    reply_ip_hdr->ip_off = htons(IP_DF);

    /* IP header -  time to live */
    reply_ip_hdr->ip_ttl = IP_INIT_TTL;

    /* IP header - protocol */
    reply_ip_hdr->ip_p = ip_protocol_icmp;

    /* IP header - checksum */
    reply_ip_hdr->ip_sum = 0;

    /* IP header - source and dest addresses */
    reply_ip_hdr->ip_src = received_ip_hdr->ip_dst;
    reply_ip_hdr->ip_dst = received_ip_hdr->ip_src;

    /* IP header - checksum */
    reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, IP_IHL_BYTES);

    /* ICMP header - type */
    reply_icmp_hdr->icmp_type = icmp_type_echo_reply;

    /* ICMP header - code */
    reply_icmp_hdr->icmp_code = 0;

    /* ICMP header - checksum */
    reply_icmp_hdr->icmp_sum = 0;

    /* ICMP header - identifier */
    reply_icmp_hdr->icmp_id = received_icmp_hdr->icmp_id;

    /* ICMP header - sequence number */
    reply_icmp_hdr->icmp_seq_num = received_icmp_hdr->icmp_seq_num;

    /* ICMP header - data */
    memcpy(reply_icmp_hdr->data, received_icmp_hdr->data, ntohs(reply_ip_hdr->ip_len) - IP_IHL_BYTES - ICMP_ECHO_HDR_SIZE);

    /* ICMP header - checksum */
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, ntohs(reply_ip_hdr->ip_len) - IP_IHL_BYTES);

    /* Create packet */
    uint8_t* frame_to_send = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t0_hdr)));
    memcpy(frame_to_send, reply_eth_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(frame_to_send + sizeof(struct sr_ethernet_hdr), reply_ip_hdr, sizeof(struct sr_ip_hdr));
    memcpy(frame_to_send + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), reply_icmp_hdr, sizeof(struct sr_icmp_t0_hdr));

    /*Send packet*/
    sr_send_packet(sr, frame_to_send, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t0_hdr), iface->name);

    free(reply_eth_hdr);
    free(reply_ip_hdr);
    free(reply_icmp_hdr);
    free(frame_to_send);
} /* end send_echo_reply */

/*
 * Method to send both ICMP type 3 and type 11 messages back
 * in the corresponding error cases.
 */
void send_icmp_t3_or_t11(struct sr_instance* sr, uint8_t* received_frame, char* from_interface, sr_icmp_type_t type, sr_icmp_dest_unreachable_code_t code)
{
    struct sr_ethernet_hdr* received_eth_hdr = (struct sr_ethernet_hdr*)received_frame;
    struct sr_ip_hdr* received_ip_hdr = (struct sr_ip_hdr*)(received_frame + sizeof(struct sr_ethernet_hdr));

    struct sr_ethernet_hdr* reply_eth_hdr = ((struct sr_ethernet_hdr*)malloc(sizeof(struct sr_ethernet_hdr)));
    struct sr_ip_hdr* reply_ip_hdr = ((struct sr_ip_hdr*)malloc(sizeof(struct sr_ip_hdr)));
    struct sr_icmp_t3_hdr* reply_icmp_hdr = ((struct sr_icmp_t3_hdr*)malloc(sizeof(struct sr_icmp_t3_hdr)));
    struct sr_if* iface = sr_get_interface(sr, from_interface);

    /* Ethernet destination address */
    int i;
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_eth_hdr->ether_dhost[i] = received_eth_hdr->ether_shost[i];

    /* Ethernet source address */
    for(i = 0; i < ETHER_ADDR_LEN; i++)
        reply_eth_hdr->ether_shost[i] = (uint8_t)iface->addr[i];

    /* Ethernet header - Type */
    reply_eth_hdr->ether_type = htons(ethertype_ip);

    /* IP header - ihl */
    reply_ip_hdr->ip_v = IPv4_VERSION;

    /* IP header - version */
    reply_ip_hdr->ip_hl = IP_IHL;

    /* IP header - Differentiated services */
    reply_ip_hdr->ip_tos = 0;

    /* IP header - total length */
    reply_ip_hdr->ip_len = received_ip_hdr->ip_len;

    /* IP header - identification */
    reply_ip_hdr->ip_id = IP_ID;

    /* IP header - fragment offset field */
    reply_ip_hdr->ip_off = htons(IP_DF);

    /* IP header -  time to live */
    reply_ip_hdr->ip_ttl = IP_INIT_TTL;

    /* IP header - protocol */
    reply_ip_hdr->ip_p = ip_protocol_icmp;

    /* IP header - checksum */
    reply_ip_hdr->ip_sum = 0;

    /* IP header - source and dest addresses */
    if(code == icmp_code_net_unreachable || code == icmp_code_host_unreachable)
    {
        reply_ip_hdr->ip_src = iface->ip;
    }
    else
    {
        reply_ip_hdr->ip_src = received_ip_hdr->ip_dst;
    }
    reply_ip_hdr->ip_dst = received_ip_hdr->ip_src;

    /* IP header - checksum */
    reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, IP_IHL_BYTES);

    /* ICMP header - type */
    reply_icmp_hdr->icmp_type = type;

    /* ICMP header - code */
    reply_icmp_hdr->icmp_code = code;

    /* ICMP header - checksum */
    reply_icmp_hdr->icmp_sum = 0;

    /* Clear unused fields to 0 */
    reply_icmp_hdr->unused = 0;
    reply_icmp_hdr->next_mtu = 0;

    /* ICMP header - data */
    memcpy(reply_icmp_hdr->data, received_ip_hdr, ICMP_DATA_SIZE);

    /* ICMP header - checksum */
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));

    /* Create packet */
    uint8_t* frame_to_send = ((uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr)));
    memcpy(frame_to_send, reply_eth_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(frame_to_send + sizeof(struct sr_ethernet_hdr), reply_ip_hdr, sizeof(struct sr_ip_hdr));
    memcpy(frame_to_send + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), reply_icmp_hdr, sizeof(struct sr_icmp_t3_hdr));

    /* Send packet */
    sr_send_packet(sr, frame_to_send, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr), iface->name);

    free(reply_eth_hdr);
    free(reply_ip_hdr);
    free(reply_icmp_hdr);
    free(frame_to_send);
} /* end send_icmp_t3_or_t11 */

/*
  Check routing table, perform LPM
*/
struct sr_if* lpm(struct sr_instance *sr, uint32_t target_ip)
{
    /* Find match interface in routing table LPM */
    struct sr_rt* curr_rt_entry = sr->routing_table;
    int longest_match = -1;
    struct sr_if* result = NULL;

    struct in_addr ip_to_in_addr;
    ip_to_in_addr.s_addr = ntohl(target_ip);

    while(curr_rt_entry != NULL)
    {
        /* Check if current routing table has longer mask than longest known so far */
        if(get_mask_len(curr_rt_entry->mask.s_addr) > longest_match)
        {
            /* Now check that we actually have a match */
            if((ip_to_in_addr.s_addr & curr_rt_entry->mask.s_addr) ==
               (ntohl(curr_rt_entry->dest.s_addr) & curr_rt_entry->mask.s_addr))
            {
                longest_match = get_mask_len(curr_rt_entry->mask.s_addr);
                result = sr_get_interface(sr, curr_rt_entry->interface);
            }
        }
        curr_rt_entry = curr_rt_entry->next;
    }
    return result;
}/* end lpm */

/*
 * Compute and return the length of a given mask.
 */
int get_mask_len(uint32_t mask)
{
    int len = 0;
    uint32_t tmp = 0x80000000;

    while(tmp != 0 && (tmp & mask) != 0)
    {
        tmp >>= 1;
        len++;
    }
    return len;
}
