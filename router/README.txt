Our implementation of the simple router starts with the call to the sr_handlepacket
method. It first performs a sanity check to confirm that the received Ethernet frame
has a minimum size (which is its header). The next thing is checking for the Ethernet
type of the received frame. We continue processing only if we receive either an ARP
or an IP packet. Otherwise the method simply returns. In case we received an ARP
packet, we check its operation code. Here again, we only recognize an ARP request
or an ARP reply. In the case of an ARP request we proceed to handle it in order to
send a reply back to the sender. For this we construct the appropriate ARP request
packet and enclose it in the Ethernet frame for sending back to the sender. In the case
of an ARP reply coming to our router, we proceed to handle that reply. Once a reply sent
to us, we record the corresponding IP to MAC address mapping in our cache. Then we
proceed to send any packets waiting for this ARP reply (since now the corresponding MAC is
known).

In the case when we receive an IP packet at the router, we proceed in one of the two
ways depending on the destination address of the packet that arrived. If the
destination of the IP packet is one of the router’s interfaces, we know that the
packet was sent for the router. In this case we look at the protocol of the IP
packet. Here we only recognize there of them. It can be either ICMP, TCP or UDP.
Otherwise we stop processing this packet. In case it’s an ICMP packet, we only proceed
if it’s an echo request, in which case we send an echo reply back to the sender.
To send an echo reply to the sender we implemented a method that constructs the
appropriate ICMP packet encapsulated in the corresponding IP packet encapsulated
in an Ethernet frame. In the case if the IP protocol is a TCP or UDP sent to one
of our interfaces we simply send a port unreachable ICMP packet back to the sender.

In the case when the IP packet that arrived has a destination address other than one
of our interfaces, then we know that this packet needs to be forwarded. This is
handled by the corresponding method.

In all cases when a packet needs to be forwarded/sent we perform an LPM to find
which interface should be used for sending the packet. Then the cache is checked
to see if we actually know the MAC address of our destination. If we do, then we
the packet to the destination. However, if we don’t then send an ARP request
(broadcast) from the appropriate interface and place the packet to be sent in
the ARP request queue to wait for the reply. In case a reply doesn’t come on time
or after 5 trials we send the corresponding ICMP massage for each packet that needed
to be sent back to the sender of that packet. We also have an implementation for
the Longest Prefix Match algorithm, which is used whenever a packets needs to be
sent from the router.


Implemented Functions

Functions to handle packets are under sr_router.c file. The longest prefix match function is also under sr_router.c.

void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

void reply_to_arp_req(struct sr_instance* sr, struct sr_ethernet_hdr* e_hdr, struct sr_arp_hdr* a_hdr, struct sr_if* iface);

void process_arp_reply(struct sr_instance* sr, struct sr_arp_hdr* arp_hdr, struct sr_if* iface);

void handle_ip_packet_for_router(struct sr_instance* sr, uint8_t* packet, struct sr_ip_hdr* ip_hdr, struct sr_if* iface);

void handle_ip_packet_to_forward(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_ip_hdr* ip_hdr, struct sr_if* iface);

void send_echo_reply(struct sr_instance* sr, uint8_t* received_frame, char* from_interface);

void send_icmp_t3_or_t11(struct sr_instance* sr, uint8_t* received_frame, char* from_interface, sr_icmp_type_t type, sr_icmp_dest_unreachable_code_t code);

struct sr_if* lpm(struct sr_instance *sr, struct in_addr target_ip);

int get_mask_len(uint32_t mask);

Functions to handle queued packets waiting for ARP reply are under sr_arpcache.c file.

void handle_arpreq(struct sr_arpreq *req, struct sr_instance *sr);

void sr_arpcache_sweepreqs(struct sr_instance *sr);