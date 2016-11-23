
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_rt.h"

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

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
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
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

void nat_handle_icmp(struct sr_instance* sr, uint8_t* received_frame, unsigned int len, struct sr_if* iface)
{
    struct sr_ip_hdr* received_ip_hdr = (struct sr_ip_hdr*)(received_frame + sizeof(struct sr_ethernet_hdr));
    struct sr_icmp_hdr* received_icmp_hdr = (struct sr_icmp_hdr*)(received_ip_hdr + (received_ip_hdr->ip_hl*4));
    sr_tcp_hdr_t* received_tcp_hdr = (sr_tcp_hdr_t*) (received_ip_hdr + (received_ip_hdr->ip_hl*4));

    /* Check ICMP packet checksum */
    uint16_t icmp_sum_temp = received_icmp_hdr->icmp_sum;
    received_icmp_hdr->icmp_sum = 0;
    int icmp_len = ntohs(received_ip_hdr->ip_len) - IP_IHL_BYTES;
    if(icmp_sum_temp != cksum(received_icmp_hdr, icmp_len))
    {
        printf("---->> Incorrect checksum of ICMP packet %u <----\n", cksum(received_icmp_hdr, icmp_len));
        return;
    }
    received_icmp_hdr->icmp_sum = icmp_sum_temp;


	if ((sr_get_interface(sr, "eth1")->ip == iface->ip) && (check_ip_for_me(sr, received_ip_hdr)))
	{
	  handle_ip_packet_for_router(sr, received_frame, len, received_ip_hdr, iface);
	}
	else if (sr_get_interface(sr, "eth1")->ip == iface->ip)
	   {
	      if ((received_icmp_hdr->icmp_type == icmp_type_echo_req)
	         || (received_icmp_hdr->icmp_type == icmp_type_echo_reply))
	      {
	    	 struct sr_icmp_t0_hdr* icmp_ping_hdr = (struct sr_icmp_t0_hdr*) received_icmp_hdr;
	    	 sr_nat_mapping_t * natLookupResult = sr_nat_lookup_internal(sr->nat, received_ip_hdr->ip_src, icmp_ping_hdr->icmp_id, nat_mapping_icmp);

	         /* No mapping? Make one! */
	         if (natLookupResult == NULL)
	         {
	            natLookupResult = sr_nat_insert_mapping(sr->nat, received_ip_hdr->ip_src, icmp_ping_hdr->icmp_id, nat_mapping_icmp);
	         }

	         natHandleReceivedOutboundIpPacket(sr, received_ip_hdr, len, iface, natLookupResult, received_frame);
	         free(natLookupResult);
	      }
	      else
	      {
	         sr_ip_hdr_t * embeddedIpPacket = NULL;
	         sr_nat_mapping_t * natLookupResult = NULL;

	         if (received_icmp_hdr->icmp_type == icmp_type_dest_unreachable)
	         {
	        	struct sr_icmp_t3_hdr * unreachableHeader = (struct sr_icmp_t3_hdr *) received_icmp_hdr;
	            embeddedIpPacket = (sr_ip_hdr_t *) unreachableHeader->data;
	         }
	         else if (received_icmp_hdr->icmp_type == icmp_type_time_exceeded)
	         {
	        	sr_icmp_t11_hdr_t * timeExceededHeader = ( sr_icmp_t11_hdr_t *) received_icmp_hdr;
	            embeddedIpPacket = (sr_ip_hdr_t *) timeExceededHeader->data;
	         }
	         else
	         {
	            return;
	         }

	         assert(embeddedIpPacket);

	         if (embeddedIpPacket->ip_p == ip_protocol_icmp)
	         {
	        	 struct sr_icmp_t0_hdr * embeddedIcmpHeader =
	               (struct sr_icmp_t0_hdr *) received_icmp_hdr;
	            if ((embeddedIcmpHeader->icmp_type == icmp_type_echo_req)
	               || (embeddedIcmpHeader->icmp_type == icmp_type_echo_reply))
	            {
	               natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
	                  embeddedIcmpHeader->icmp_id, nat_mapping_icmp);
	            }
	         }
	         else if (embeddedIpPacket->ip_p == ip_protocol_tcp)
	         {
	            sr_tcp_hdr_t * embeddedTcpHeader = received_tcp_hdr;
	            natLookupResult = sr_nat_lookup_internal(sr->nat, embeddedIpPacket->ip_dst,
	               embeddedTcpHeader->destinationPort, nat_mapping_tcp);
	         }
	         else
	         {
	            return;
	         }

	         if (natLookupResult != NULL)
	         {
	            natHandleReceivedOutboundIpPacket(sr, received_ip_hdr, len, iface,
	               natLookupResult, received_frame);
	            free(natLookupResult);
	         }
	      }
	   }
	   else
	   {

	   }

}

bool check_ip_for_me(struct sr_instance* sr, struct sr_ip_hdr* ip_packet)
{

    struct sr_if* curr_if = sr->if_list;
    while(curr_if != NULL)
    {
        if (ip_packet->ip_dst == curr_if->ip)
        {
            printf("---->> Received IP packet for me <----\n");

            return true;
        }
        curr_if = curr_if->next;
    }

   return false;
}

static void natHandleReceivedOutboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, struct sr_if* receivedInterface, sr_nat_mapping_t * natMapping, uint8_t* received_frame)
{
   if (packet->ip_p == ip_protocol_icmp)
   {
      sr_icmp_hdr_t *icmpPacketHeader = (sr_icmp_hdr_t *) (((uint8_t*) packet)
         + (packet->ip_hl*4));

      if ((icmpPacketHeader->icmp_type == icmp_type_echo_req)
         || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t* rewrittenIcmpHeader = (sr_icmp_t0_hdr_t*) icmpPacketHeader;
         int icmpLength = length - (packet->ip_hl*4);

         assert(natMapping);

         /* Handle ICMP identify remap and validate. */
         rewrittenIcmpHeader->icmp_id = natMapping->aux_ext;
         rewrittenIcmpHeader->icmp_sum = 0;
         rewrittenIcmpHeader->icmp_sum = cksum(rewrittenIcmpHeader, icmpLength);

         /* Handle IP address remap and validate. */
         struct sr_rt* rt = lpm(sr, ntohl(packet->ip_dst));
         packet->ip_src = sr_get_interface(sr,rt->interface)->ip;

         handle_ip_packet_to_forward(sr, received_frame, length, packet, receivedInterface);
      }
      else
      {
    	  int icmpLength = length - (packet->ip_hl*4);
         sr_ip_hdr_t * originalDatagram;
         if (icmpPacketHeader->icmp_type == icmp_type_dest_unreachable)
         {
            /* This packet is actually associated with a stream. */
            sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }
         else if (icmpPacketHeader->icmp_type == icmp_type_time_exceeded)
         {
            sr_icmp_t11_hdr_t *unreachablePacketHeader = (sr_icmp_t11_hdr_t *) icmpPacketHeader;
            originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         }

         assert(natMapping);

         if (originalDatagram->ip_p == ip_protocol_tcp)
         {
            sr_tcp_hdr_t *originalTransportHeader = (sr_tcp_hdr_t*) (packet + (packet->ip_hl*4));

            /* Perform mapping on embedded payload */
            originalTransportHeader->destinationPort = natMapping->aux_ext;
            originalDatagram->ip_dst = sr_get_interface(sr,
            		lpm(sr, ntohl(packet->ip_dst))->interface)->ip;
         }
         else if (originalDatagram->ip_p == ip_protocol_icmp)
         {
            sr_icmp_t0_hdr_t *originalTransportHeader =
               (sr_icmp_t0_hdr_t *) (packet + (packet->ip_hl*4));

            /* Perform mapping on embedded payload */
            originalTransportHeader->icmp_id = natMapping->aux_ext;
            originalDatagram->ip_dst = sr_get_interface(sr,
               lpm(sr, ntohl(packet->ip_dst))->interface)->ip;
         }

         /* Update ICMP checksum */
         icmpPacketHeader->icmp_sum = 0;
         icmpPacketHeader->icmp_sum = cksum(icmpPacketHeader, icmpLength);

         /* Rewrite actual packet header. */
         struct sr_rt* rt = lpm(sr, ntohl(packet->ip_dst));
         packet->ip_src = sr_get_interface(sr,rt->interface)->ip;

         handle_ip_packet_to_forward(sr, received_frame, length, packet, receivedInterface);

      }
   }
   else if (packet->ip_p == ip_protocol_tcp)
   {
      sr_tcp_hdr_t* tcpHeader = (sr_tcp_hdr_t *) (((uint8_t*) packet) + (packet->ip_hl*4));

      tcpHeader->sourcePort = natMapping->aux_ext;
      packet->ip_src = sr_get_interface(sr,
         lpm(sr, ntohl(packet->ip_dst))->interface)->ip;

      natRecalculateTcpChecksum(packet, length);
      handle_ip_packet_to_forward(sr, received_frame, length, packet, receivedInterface);
   }
   /* If another protocol, should have been dropped by now. */
}

static void natRecalculateTcpChecksum(sr_ip_hdr_t * tcpPacket, unsigned int length)
{
   unsigned int tcpLength = length - (tcpPacket->ip_hl*4);
   uint8_t *packetCopy = malloc(sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   sr_tcp_ip_pseudo_hdr_t * checksummedHeader = (sr_tcp_ip_pseudo_hdr_t *) packetCopy;
   sr_tcp_hdr_t * const tcpHeader = (sr_tcp_hdr_t * const ) (((uint8_t*) tcpPacket)
      + (tcpPacket->ip_hl*4));

   /* I wish there was a better way to do this with pointer magic, but I don't
    * see it. Make a copy of the packet and prepend the IP pseudo-header to
    * the front. */
   memcpy(packetCopy + sizeof(sr_tcp_ip_pseudo_hdr_t), tcpHeader, tcpLength);
   checksummedHeader->sourceAddress = tcpPacket->ip_src;
   checksummedHeader->destinationAddress = tcpPacket->ip_dst;
   checksummedHeader->zeros = 0;
   checksummedHeader->protocol = ip_protocol_tcp;
   checksummedHeader->tcpLength = htons(tcpLength);

   tcpHeader->checksum = 0;
   tcpHeader->checksum = cksum(packetCopy, sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);

   free(packetCopy);
}
