
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
		  nat_send_icmp_t3(sr, packet, 0, ip_hdr->ip_dst);

        return;
	}
	 /*Outbound*/
	else if (sr_get_interface(sr, INTERNAL_INTERFACE)->ip == iface->ip)
	{

	  struct sr_nat_mapping *nat_lookup_result = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->src_port, nat_mapping_tcp);

	  /* No mapping*/
	  if (nat_lookup_result == NULL)
	  {
		sleep(6.0);
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
	    	  if(ntohs(tcp_hdr->dst_port) >= 1024 && ntohs(tcp_hdr->src_port) >= 1024)
	    	  {
	    		  sleep(6);
	    		  nat_send_icmp_t3(sr, packet, 0, ip_hdr->ip_dst);

	    	  }
	    	  else
	    	  {
	    		  nat_send_icmp_t3(sr, packet, 0, ip_hdr->ip_dst);

	    	  }
		}
	}
}

void nat_send_icmp_t3(struct sr_instance* sr, uint8_t* pkt, int len, uint32_t ip_sip)
{

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
	struct sr_rt *rt = lpm(sr, ip_hdr->ip_src);
	if (!rt) return;

	uint8_t *new_pkt = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)new_pkt;
	enum sr_ethertype ethertype = ethertype_ip;
	eth_hdr->ether_type = htons(ethertype);

	sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
	enum sr_ip_protocol protocol = ip_protocol_icmp;
	new_ip_hdr->ip_v = 4;
	new_ip_hdr->ip_hl = 5;
	new_ip_hdr->ip_tos = 0;
	new_ip_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) + sizeof(sr_icmp_t3_hdr_t));
	new_ip_hdr->ip_id = 0x0000;
	new_ip_hdr->ip_off = htons(IP_DF);
	new_ip_hdr->ip_ttl = INIT_TTL;
	new_ip_hdr->ip_p = protocol;
	new_ip_hdr->ip_src = ip_sip;
	new_ip_hdr->ip_dst = ip_hdr->ip_src;
	new_ip_hdr->ip_sum = 0x0000;
	new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

	sr_ip_hdr_t *buf_ip_hdr = (sr_ip_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(new_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	icmp_hdr->icmp_type = icmp_type_dest_unreachable;
	icmp_hdr->icmp_code = icmp_code_port_unreachable;
	icmp_hdr->unused = 0;
	icmp_hdr->next_mtu = 0;
	memcpy(icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(buf_ip_hdr->ip_len) - (buf_ip_hdr->ip_hl * 4));


	struct sr_arpentry *arpentry = sr_arpcache_lookup(&(sr->cache), rt->gw.s_addr);
	if (arpentry)
	{
	  struct sr_if* interface = sr_get_interface(sr, rt->interface);
	  memcpy(eth_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
	  memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
	  sr_send_packet(sr, new_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), rt->interface);
	  free(arpentry);
	}
	else
	{
	  struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, new_pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), rt->interface);
		   handle_arpreq(req, sr);
	}
	free(new_pkt);
}
