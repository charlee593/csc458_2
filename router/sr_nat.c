
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->icmp_id = STARTING_PORT_NUMBER;
  nat->tcp_port_num = STARTING_PORT_NUMBER;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr)
{  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type )
{

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping)
  {

	if (mapping->type == type && mapping->aux_ext == aux_ext)
	{
		mapping->last_updated = time(NULL);
		copy = malloc(sizeof(struct sr_nat_mapping));
		memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
		break;
	}

    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while (mapping)
  {

	if (mapping->type == type &&  mapping->ip_int == ip_int && mapping->aux_int == aux_int )
	{
		mapping->last_updated = time(NULL);
		copy = malloc(sizeof(struct sr_nat_mapping));
		memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
		break;
	}

    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *)malloc(sizeof(struct sr_nat_mapping));

  struct sr_if *int_iface = sr_get_interface(nat->sr,"eth1");
  struct sr_if *iface = nat->sr->if_list;
  while(iface)
  {
	if (iface != int_iface)
	{
		mapping->ip_ext = iface->ip;
		break;
	}
	iface = iface->next;
  }

  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->conns = NULL;
  mapping->aux_ext = htons(get_port_num(nat, type));
  mapping->last_updated = time(NULL);
  mapping->next = nat->mappings;
  nat->mappings = mapping;
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void handle_nat_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
	uint8_t ip_protocol = ip_hdr->ip_p;

	/*NAT icmp*/
	if (ip_protocol == ip_protocol_icmp)
	{
		nat_handle_icmp(sr, packet, len, interface);
	}
	else if (ip_protocol == ip_protocol_tcp)
	{
		nat_handle_tcp(sr, packet, len, interface);
	}
}

int get_port_num(struct sr_nat *nat, sr_nat_mapping_type type)
{
	uint16_t curr_port;
	struct sr_nat_mapping * curr_mapping = nat->mappings;
	if (type == nat_mapping_icmp)
	{
		curr_port = nat->icmp_id;
	}
	else if (type == nat_mapping_tcp)
	{
		curr_port = nat->tcp_port_num;
	}

	/*Find a port that is not used*/
	while (curr_mapping)
	{
		if ((curr_mapping->type == type) && (htons(curr_port) == curr_mapping->aux_ext))
		{
			curr_port++;
			curr_mapping = nat->mappings;
		}
		else
		{
			curr_mapping = curr_mapping->next;
		}
	}

	if (type == nat_mapping_icmp)
	{
		nat->icmp_id = curr_port + 1;
	}
	else if (type == nat_mapping_tcp)
	{
		nat->tcp_port_num = curr_port + 1;
	}

   return curr_port;
}

void nat_handle_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_if* iface = sr_get_interface(sr, interface);
	struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
	int ip_hl = ip_hdr->ip_hl * 4;

	sr_icmp_t0_hdr_t *icmp_hdr = (sr_icmp_t0_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	/* Outbound */
	if (sr_get_interface(sr, INTERNAL_INTERFACE)->ip == iface->ip)
	{

	  struct sr_nat_mapping *nat_lookup_result = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);

	  /* No mapping */
	  if (!nat_lookup_result)
	  {
		nat_lookup_result = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_id, nat_mapping_icmp);
	  }

	  /* Translate header */
	  ip_hdr->ip_src = sr_get_interface(sr, EXTERNAL_INTERFACE)->ip;

	  icmp_hdr->icmp_id = nat_lookup_result->aux_ext;
	  icmp_hdr->icmp_sum = 0;
	  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);

	  ip_hdr->ip_sum = 0;
	  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

	  handle_ip_packet_to_forward(sr, packet, len, ip_hdr, iface);

	}
	/* Inbound */
	else if (sr_get_interface(sr, EXTERNAL_INTERFACE)->ip == iface->ip)
	{

	  struct sr_nat_mapping *nat_lookup_result = sr_nat_lookup_external(sr->nat, icmp_hdr->icmp_id, nat_mapping_icmp);

	  if (nat_lookup_result)
	  {

		ip_hdr->ip_dst = nat_lookup_result->ip_int;
		icmp_hdr->icmp_id = nat_lookup_result->aux_int;
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hl);
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);

		free(nat_lookup_result);
		handle_ip_packet_to_forward(sr, packet, len, ip_hdr, iface);

	  }
	  else
	  {
		sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

		/* ICMP echo request or reply*/
		if (icmp_hdr->icmp_type == icmp_type_echo_req || icmp_hdr->icmp_code == icmp_type_echo_reply)
		{

			/* Check ICMP packet checksum */
			uint16_t icmp_sum_temp = icmp_hdr->icmp_sum;
			icmp_hdr->icmp_sum = 0;
			int icmp_len = ntohs(ip_hdr->ip_len) - ip_hl;
			if(icmp_sum_temp == cksum(icmp_hdr, icmp_len))
			{
				icmp_hdr->icmp_sum = icmp_sum_temp;
				send_echo_reply(sr, packet, interface, len);
				return;
			}

		}
	  }

	}
	else
	{
		/*Bad packet*/
		return;
	}
}


void nat_handle_tcp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
	struct sr_if* iface = sr_get_interface(sr, interface);
	struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(sr_ethernet_hdr_t));

	sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));


	/* Check if it is for me - find interfaces name */
	struct sr_if* curr_if = sr->if_list;
	while(curr_if != NULL)
	{
		if (ip_hdr->ip_dst == curr_if->ip)
		{
			printf("---->> Received IP packet for me <----\n");
			break;
		}
		curr_if = curr_if->next;
	}

	if ((sr_get_interface(sr, INTERNAL_INTERFACE)->ip == iface->ip) && curr_if)
	{
	      nat_send_icmp_t3(sr, icmp_code_port_unreachable, ip_hdr);

        return;
	}
	 /*Outbound*/
	else if (sr_get_interface(sr, INTERNAL_INTERFACE)->ip == iface->ip)
	{

	  struct sr_nat_mapping *nat_lookup_result = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, nat_mapping_tcp);

	  /* No mapping*/
	  if (!nat_lookup_result)
	  {
		nat_lookup_result = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, nat_mapping_tcp);
	  }

	   /*Translate header*/
	  ip_hdr->ip_src = nat_lookup_result->ip_ext;
	  tcp_hdr->src_port = nat_lookup_result->aux_ext;
	  ip_hdr->ip_sum = 0;
	  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
	  tcp_hdr->tcp_sum = 0;


	  unsigned int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
	  unsigned int total_len = sizeof(sr_tcp_pseudo_hdr_t) + tcp_len;
	  uint8_t *temp_hdr_buf = malloc(total_len);
	  sr_tcp_pseudo_hdr_t *temp_hdr = (sr_tcp_pseudo_hdr_t *)temp_hdr_buf;

	  temp_hdr->ip_src = ip_hdr->ip_src;
	  temp_hdr->ip_dst = ip_hdr->ip_dst;
	  temp_hdr->pad = 0;
	  temp_hdr->ip_p = ip_hdr->ip_p;
	  temp_hdr->length = htons(tcp_len);

	  memcpy(temp_hdr_buf + sizeof(sr_tcp_pseudo_hdr_t), tcp_hdr, tcp_len);

	  tcp_hdr->tcp_sum = cksum(temp_hdr_buf, total_len);

	  free(temp_hdr_buf);
	  free(nat_lookup_result);
	  handle_ip_packet_to_forward(sr, packet, len, ip_hdr, iface);
	}
	 /*Inbound*/
	else if (sr_get_interface(sr, EXTERNAL_INTERFACE)->ip == iface->ip)
	{

		struct sr_nat_mapping *nat_lookup_result = sr_nat_lookup_external(sr->nat, tcp_hdr->dst_port, nat_mapping_tcp);

		if (nat_lookup_result)
		{
			ip_hdr->ip_dst = nat_lookup_result->ip_int;
			tcp_hdr->dst_port = nat_lookup_result->aux_int;
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
			tcp_hdr->tcp_sum = 0;

			unsigned int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
			unsigned int total_len = sizeof(sr_tcp_pseudo_hdr_t) + tcp_len;
			uint8_t *temp_hdr_buf = malloc(total_len);
			sr_tcp_pseudo_hdr_t *temp_hdr = (sr_tcp_pseudo_hdr_t *)temp_hdr_buf;

			temp_hdr->ip_src = ip_hdr->ip_src;
			temp_hdr->ip_dst = ip_hdr->ip_dst;
			temp_hdr->pad = 0;
			temp_hdr->ip_p = ip_hdr->ip_p;
			temp_hdr->length = htons(tcp_len);

			memcpy(temp_hdr_buf + sizeof(sr_tcp_pseudo_hdr_t), tcp_hdr, tcp_len);

			tcp_hdr->tcp_sum = cksum(temp_hdr_buf, total_len);

			free(temp_hdr_buf);
			free(nat_lookup_result);
			handle_ip_packet_to_forward(sr, packet, len, ip_hdr, iface);

		}
		else
		{
			return;
		}
	}
}

void nat_send_icmp_t3(struct sr_instance* sr, sr_icmp_dest_unreachable_code_t icmpCode, sr_ip_hdr_t* originalPacketPtr)
{
	struct sr_rt* iface;

	uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
	+ sizeof(sr_icmp_t3_hdr_t));
	sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
	+ sizeof(sr_ip_hdr_t));


	replyIpHeader->ip_v = IPv4_VERSION;
	replyIpHeader->ip_hl = IP_IHL;
	replyIpHeader->ip_tos = 0;
	replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	replyIpHeader->ip_id = 0;
	replyIpHeader->ip_off = htons(IP_DF);
	replyIpHeader->ip_ttl = IP_INIT_TTL;
	replyIpHeader->ip_p = ip_protocol_icmp;
	replyIpHeader->ip_sum = 0;
	replyIpHeader->ip_dst = originalPacketPtr->ip_src; /* Already in network byte order. */


	iface = lpm(sr, replyIpHeader->ip_dst);

	replyIpHeader->ip_src = originalPacketPtr->ip_dst;
	replyIpHeader->ip_sum = cksum(replyIpHeader, sizeof(struct sr_ip_hdr));

	replyIcmpHeader->icmp_type = icmp_type_dest_unreachable;
	replyIcmpHeader->icmp_code = icmpCode;
	replyIcmpHeader->icmp_sum = 0;
	replyIcmpHeader->unused = 0;
	replyIcmpHeader->next_mtu = 0;
	memcpy(replyIcmpHeader->data, originalPacketPtr, ICMP_DATA_SIZE);
	replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));

	uint32_t nextHopIpAddress;
	struct sr_arpentry *arpEntry;

	sr_ethernet_hdr_t* packet = (sr_ethernet_hdr_t*) replyPacket;

	nextHopIpAddress = ntohl(iface->gw.s_addr);
	arpEntry = sr_arpcache_lookup(&sr->cache, replyIpHeader->ip_dst);

	packet->ether_type = htons(ethertype_ip);
	memcpy(packet->ether_shost, sr_get_interface(sr, iface->interface)->addr, ETHER_ADDR_LEN);

	struct sr_rt *rt = lpm(sr, originalPacketPtr->ip_dst);

	if (arpEntry != NULL)
	{
	struct sr_if* out_if = sr_get_interface(sr, rt->interface);
	memcpy(packet->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
	memcpy(packet->ether_shost, out_if->addr, ETHER_ADDR_LEN);

	sr_send_packet(sr, (uint8_t*) packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), rt->interface);

	free(arpEntry);
	}
	else
	{
	struct sr_arpreq* arpRequestPtr = sr_arpcache_queuereq(&sr->cache, ntohl(iface->gw.s_addr),
	(uint8_t*) packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), iface->interface);

	uint8_t* arpPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) arpPacket;
	sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*) (arpPacket + sizeof(sr_ethernet_hdr_t));
	assert(arpPacket);

	/* Ethernet Header */
	static const uint8_t broadcastEthernetAddress[ETHER_ADDR_LEN] =
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	memcpy(ethernetHdr->ether_dhost, broadcastEthernetAddress, ETHER_ADDR_LEN);
	memcpy(ethernetHdr->ether_shost, sr_get_interface(sr, iface->interface)->addr, ETHER_ADDR_LEN);
	ethernetHdr->ether_type = htons(ethertype_arp);

	/* ARP Header */
	arpHdr->ar_hrd = htons(arp_hrd_ethernet);
	arpHdr->ar_pro = htons(ethertype_ip);
	arpHdr->ar_hln = ETHER_ADDR_LEN;
	arpHdr->ar_pln = 4;
	arpHdr->ar_op = htons(arp_op_request);
	memcpy(arpHdr->ar_sha, sr_get_interface(sr, iface->interface)->addr, ETHER_ADDR_LEN);
	arpHdr->ar_sip = sr_get_interface(sr, iface->interface)->ip;
	memset(arpHdr->ar_tha, 0, ETHER_ADDR_LEN);
	arpHdr->ar_tip = htonl(arpRequestPtr->ip);

	/* Ship it! */
	sr_send_packet(sr, arpPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
		 sr_get_interface(sr, iface->interface)->name);

	free(arpPacket);

	arpRequestPtr->times_sent = 1;
	arpRequestPtr->sent = time(NULL);
	}

	free(replyPacket);
}
