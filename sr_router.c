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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

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

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  sr_ip_hdr_t *ihdr;
  sr_arp_hdr_t *arp_hdr;
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n*** -> Received packet of length %d \n", len);
  printf("\n*** -> Interface %s \n", interface);
  print_hdrs(packet, len);
  /* fill in code here */

  /* Parse Ethernet Header*/
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength)
  {
    fprintf(stderr, "Failed to parse ETHERNET header, insufficient length %d\n", len);
    return;
  }

  uint16_t ethtype = ethertype(packet);
  /*print_hdr_eth(packet);*/

  if (ethtype == ethertype_ip) /* IP */
  {
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength)
    {
      fprintf(stderr, "Failed to parse IP header, insufficient length %d\n", len);
      return;
    }

    ihdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if (!amithetarget(sr, ihdr->ip_dst)) /* forwarding request when dest ip does not belong to router */
    {
      /* Decrement the TTL by 1 */
      ihdr->ip_ttl -= 1;

      if (ihdr->ip_ttl <= 0)
      {
        fprintf(stderr, "\nTTL Expired\n");
        send_icmp_ttl_expired(sr, packet, len, interface);
        return;
      }
      fprintf(stderr, "Forwarding Request\n");
      /*print_addr_ip_int(ntohl(ihdr->ip_dst));*/
      forward_ip_request(sr, packet, len, interface);
      return;
    }

    /*print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));*/
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
    fprintf(stderr, "ip proto : %d\n", ip_proto);
    if (ip_proto == ip_protocol_icmp) /* ICMP */
    {
      minlength += sizeof(sr_icmp_hdr_t);
      if (len < minlength)
      {
        fprintf(stderr, "Failed to parse ICMP header, insufficient length %d\n", len);
        return;
      }
      sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      /*print_hdr_icmp((uint8_t *)icmphdr);*/
      if (icmphdr->icmp_type == ICMP_ECHO_REQUEST)
      {
        /*print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/
        fprintf(stderr, "ICMP echo request\n");
        send_icmp_echo_reply(sr, packet, len, interface);
        return;
      }
    }
    else if (ip_proto == ip_protocol_udp || ip_proto == ip_protocol_tcp) /* send icmp port unreachable */
    {
      send_icmp_port_unreachable(sr, packet, len, interface);
    }
  }
  else if (ethtype == ethertype_arp) /* ARP */
  {
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength)
    {
      fprintf(stderr, "Failed to parse ARP header, insufficient length %d\n", len);
    }
    else
    {
      /*print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));*/
      arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      if (amithetarget(sr, arp_hdr->ar_tip))
      {
        if (ntohs(arp_hdr->ar_op) == arp_op_request) /* ARP Request to me */
        {
          fprintf(stderr, "ARP Request Received from address : ");
          /*print_addr_eth(arp_hdr->ar_sha);*/
          /* send a packet back */
          setup_and_send_ARPreply(sr, packet /* lent */, len);
        }
        else if (ntohs(arp_hdr->ar_op) == arp_op_reply) /* ARP Reply to me */
        {
        }
        else /* drop packet */
        {
          fprintf(stderr, "ARP OP not recognised : %d\n", ntohs(arp_hdr->ar_op));
        }
      }
    }
  }
  else /* Drop Packet */
  {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }

} /* end sr_ForwardPacket */

/* Helper Functions */

/*---------------------------------------------------------------------
 * Method: amithetarget(struct sr_instance *sr, uint32_t tip)
 * Scope:  Local
 *
 * This method is called to check if the target ip matches with router's 
 * one of the interface ips
 * Returns 1 if it is the target and 0 otherwise
 *---------------------------------------------------------------------*/
int amithetarget(struct sr_instance *sr, uint32_t tip)
{
  struct sr_if *if_walker = 0;

  if (!sr->if_list)
  {
    fprintf(stderr, "Interface list empty \n");
    return -1;
  }

  if_walker = sr->if_list;

  /* sr_print_if_list(sr); */

  while (if_walker)
  {

    if (if_walker->ip == tip)
    {
      return 1;
    }
    if_walker = if_walker->next;
    /*sr_print_if(if_walker);*/
  }
  return 0;
}

/* This method is called to check if the target ip matches with router's 
 * one of the interface ips
 *---------------------------------------------------------------------*/
void setup_and_send_ARPreply(struct sr_instance *sr, uint8_t *packet, unsigned int len)
{
  uint8_t *packet_copy = malloc(len);
  memcpy(packet_copy, packet, len);
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet_copy;
  sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *ahdr = (sr_arp_hdr_t *)(packet_copy + sizeof(sr_ethernet_hdr_t));
  sr_arp_hdr_t *old_ahdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned char mac_addr[ETHER_ADDR_LEN];
  struct sr_if *intface = get_interface_from_ip(sr, old_ahdr->ar_tip);
  if (!intface)
  {
    fprintf(stderr, "Interface mac addr could not be found from interface ip \n");
    return;
  }

  /* set src and dest mac addr */
  memcpy(mac_addr, intface->addr, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_dhost, old_ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, (uint8_t *)mac_addr, ETHER_ADDR_LEN);

  /* set arp data */
  ahdr->ar_op = htons(arp_op_reply);
  ahdr->ar_sip = old_ahdr->ar_tip;
  ahdr->ar_tip = old_ahdr->ar_sip;
  memcpy(ahdr->ar_sha, (uint8_t *)mac_addr, ETHER_ADDR_LEN);
  memcpy(ahdr->ar_tha, old_ahdr->ar_sha, ETHER_ADDR_LEN);

  fprintf(stderr, "printing packet to be sent\n");
  print_hdr_eth(packet_copy);
  print_hdr_arp(packet_copy + sizeof(sr_ethernet_hdr_t));

  sr_send_packet(sr, packet_copy, len, intface->name);

  free(packet_copy);
  return;
} /* -- setupARPreply -- */

/* Given an interface ip return the interface record or 0 if it doesn't
 * exist.
 *---------------------------------------------------------------------*/
struct sr_if *get_interface_from_ip(struct sr_instance *sr, const uint32_t ip)
{
  struct sr_if *if_walker = 0;

  /* -- REQUIRES -- */
  assert(ip);
  assert(sr);

  if_walker = sr->if_list;

  while (if_walker)
  {
    if (if_walker->ip == ip)
    {
      return if_walker;
    }
    if_walker = if_walker->next;
  }

  return 0;
} /* -- get_interface_from_ip -- */

/* Sends ICMP ttl expired reply to the source
 *---------------------------------------------------------------------*/
void send_icmp_ttl_expired(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ihdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint8_t temp_ether_shost[ETHER_ADDR_LEN];
  uint32_t temp_ip_src;

  /* reverse src and dest MAC addr */
  memcpy(temp_ether_shost, ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_dhost, temp_ether_shost, ETHER_ADDR_LEN);

  /* set src and dest IP addr */
  temp_ip_src = ihdr->ip_src;
  ihdr->ip_src = ihdr->ip_dst;
  ihdr->ip_dst = temp_ip_src;
  ihdr->ip_ttl = INIT_TTL;
  ihdr->ip_p = ip_protocol_icmp;
  ihdr->ip_off = htons(IP_DF);
  ihdr->ip_sum = INITIAL_SUM;
  ihdr->ip_sum = cksum(ihdr, sizeof(sr_ip_hdr_t));

  /* set icmp header */
  icmphdr->icmp_type = ICMP_TTL_EXPIRED;
  icmphdr->icmp_code = DEFAULT_CODE;
  icmphdr->icmp_sum = INITIAL_SUM;
  icmphdr->icmp_sum = cksum(icmphdr, sizeof(sr_icmp_hdr_t));

  fprintf(stderr, "\nPrinting packet to be sent as icmp echo\n");
  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, interface);

  return;
}

struct sr_rt *sr_rt_lpm_lookup(struct sr_instance *sr, sr_ip_hdr_t *ihdr)
{
  struct sr_rt *rt_cur_row, *rt_lpm_row;
  uint32_t in_masked_ip, rt_masked_ip;
  /* sr_print_routing_table(sr); */
  rt_cur_row = sr->routing_table;
  rt_lpm_row = NULL;
  while (rt_cur_row != (struct sr_rt *)NULL)
  {
    rt_masked_ip = rt_cur_row->dest.s_addr & rt_cur_row->mask.s_addr;
    in_masked_ip = ihdr->ip_dst & rt_cur_row->mask.s_addr;
    if (rt_masked_ip == in_masked_ip)
    {
      rt_lpm_row = rt_lpm_row ? ((rt_cur_row->mask.s_addr > rt_lpm_row->mask.s_addr) ? rt_cur_row : rt_lpm_row) : rt_cur_row;
    }
    rt_cur_row = rt_cur_row->next;
  }
  return rt_lpm_row;
}

void forward_ip_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  sr_ip_hdr_t *ihdr;
  sr_ethernet_hdr_t *ehdr;
  struct sr_rt *rt_row;
  struct sr_arpentry *arpcache_row;

  /* Sanity-check already done in caller function */

  ehdr = (sr_ethernet_hdr_t *)(packet);
  ihdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Re-compute the packet checksum over the modified header; TTL decremented in caller function */
  ihdr->ip_sum = INITIAL_SUM;
  ihdr->ip_sum = cksum(ihdr, sizeof(sr_ip_hdr_t));

  /* lookup longest prefix match in routing table to get the next-hop ip */
  rt_row = sr_rt_lpm_lookup(sr, ihdr);
  /*fprintf(stderr, "\nlpm lookup result : %s\n", rt_row->interface);
  fprintf(stderr, "\nlpm lookup gw : ");
  print_addr_ip_int(ntohl(rt_row->gw.s_addr));
  fprintf(stderr, "\nlpm lookup dest : ");
  print_addr_ip_int(ntohl(rt_row->dest.s_addr));*/

  if (rt_row == (struct sr_rt *)NULL) /* Dest IP addr not in routing table; send icmp net unreachable */
  {
    send_icmp_net_unreachable(sr, packet, len, interface);
    return;
  }

  /* lookup ARP cache to get next hop MAC */
  arpcache_row = sr_arpcache_lookup(&sr->cache, ihdr->ip_dst);
  if (arpcache_row == NULL)
  {
    /* if cache miss, send an ARP request for the next-hop IP and add the
     * packet to the queue of packets waiting on this ARP request */
    fprintf(stderr, "\nARP Cache Miss for ip : ");
    print_addr_ip_int(ntohl(ihdr->ip_dst));

    return;
  }

  /* set the new src, dest mac addr of packet */
  memcpy(ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_dhost, (uint8_t *)arpcache_row->mac, ETHER_ADDR_LEN);

  sr_send_packet(sr, packet, len, rt_row->interface);

  return;
}

void send_icmp_net_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  uint8_t *t3_packet;
  unsigned int t3_len;
  sr_ethernet_hdr_t *ehdr, *t3_ehdr;
  sr_ip_hdr_t *ihdr, *t3_ihdr;
  sr_icmp_t3_hdr_t *t3_icmphdr;

  fprintf(stderr, "\nSending ICMP net unreachable\n");

  /* need to construct a new packet since icmp type3 header format is different */
  t3_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  t3_packet = malloc(t3_len);
  memcpy(t3_packet, packet, len);
  ehdr = (sr_ethernet_hdr_t *)packet;
  t3_ehdr = (sr_ethernet_hdr_t *)t3_packet;

  /* reverse src and dest MAC addr */
  memcpy(t3_ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(t3_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);

  ihdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  t3_ihdr = (sr_ip_hdr_t *)(t3_packet + sizeof(sr_ethernet_hdr_t));

  /* set IP header */
  t3_ihdr->ip_src = ihdr->ip_dst;
  t3_ihdr->ip_dst = ihdr->ip_src;
  t3_ihdr->ip_ttl = INIT_TTL;
  t3_ihdr->ip_p = ip_protocol_icmp;
  t3_ihdr->ip_off = htons(IP_DF);
  t3_ihdr->ip_tos = TOS_BEST_EFFORT;
  t3_ihdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  t3_ihdr->ip_sum = INITIAL_SUM;
  t3_ihdr->ip_sum = cksum(t3_ihdr, sizeof(sr_ip_hdr_t));

  t3_icmphdr = (sr_icmp_t3_hdr_t *)(t3_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* set icmp header */
  memset(t3_icmphdr, 0, sizeof(sr_icmp_t3_hdr_t));
  t3_icmphdr->icmp_type = ICMP_UNREACHABLE;
  t3_icmphdr->icmp_code = ICMP_NET_UNREACHABLE;
  t3_icmphdr->unused = 0;
  t3_icmphdr->next_mtu = 0;
  memset(t3_icmphdr->data, 0, ICMP_DATA_SIZE);
  memcpy(t3_icmphdr->data, ihdr, ICMP_DATA_SIZE);
  t3_icmphdr->icmp_sum = INITIAL_SUM;
  t3_icmphdr->icmp_sum = cksum(t3_icmphdr, sizeof(sr_icmp_t3_hdr_t));

  print_hdrs(t3_packet, t3_len);
  sr_send_packet(sr, t3_packet, t3_len, interface);
  free(t3_packet);

  return;
}

void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  uint8_t *t3_packet;
  unsigned int t3_len;
  sr_ethernet_hdr_t *ehdr, *t3_ehdr;
  sr_ip_hdr_t *ihdr, *t3_ihdr;
  sr_icmp_t3_hdr_t *t3_icmphdr;

  fprintf(stderr, "\nSending ICMP port unreachable\n");

  /* need to construct a new packet since icmp type3 header format is different */
  t3_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  t3_packet = malloc(t3_len);
  memcpy(t3_packet, packet, len);
  ehdr = (sr_ethernet_hdr_t *)packet;
  t3_ehdr = (sr_ethernet_hdr_t *)t3_packet;

  /* reverse src and dest MAC addr */
  memcpy(t3_ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(t3_ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);

  ihdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  t3_ihdr = (sr_ip_hdr_t *)(t3_packet + sizeof(sr_ethernet_hdr_t));

  /* set IP header */
  t3_ihdr->ip_src = ihdr->ip_dst;
  t3_ihdr->ip_dst = ihdr->ip_src;
  t3_ihdr->ip_ttl = INIT_TTL;
  t3_ihdr->ip_p = ip_protocol_icmp;
  t3_ihdr->ip_off = htons(IP_DF);
  t3_ihdr->ip_tos = TOS_BEST_EFFORT;
  t3_ihdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  t3_ihdr->ip_sum = INITIAL_SUM;
  t3_ihdr->ip_sum = cksum(t3_ihdr, sizeof(sr_ip_hdr_t));

  t3_icmphdr = (sr_icmp_t3_hdr_t *)(t3_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* set icmp header */
  memset(t3_icmphdr, 0, sizeof(sr_icmp_t3_hdr_t));
  t3_icmphdr->icmp_type = ICMP_UNREACHABLE;
  t3_icmphdr->icmp_code = ICMP_PORT_UNREACHABLE;
  t3_icmphdr->unused = 0;
  t3_icmphdr->next_mtu = 0;
  memset(t3_icmphdr->data, 0, ICMP_DATA_SIZE);
  memcpy(t3_icmphdr->data, ihdr, ICMP_DATA_SIZE);
  t3_icmphdr->icmp_sum = INITIAL_SUM;
  t3_icmphdr->icmp_sum = cksum(t3_icmphdr, sizeof(sr_icmp_t3_hdr_t));

  print_hdrs(t3_packet, t3_len);
  sr_send_packet(sr, t3_packet, t3_len, interface);
  free(t3_packet);

  return;
}

void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ihdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint8_t temp_ether_shost[ETHER_ADDR_LEN];
  uint32_t temp_ip_src;

  /* reverse src and dest MAC addr */
  memcpy(temp_ether_shost, ehdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_dhost, temp_ether_shost, ETHER_ADDR_LEN);

  /* reverse src and dest IP addr */
  temp_ip_src = ihdr->ip_src;
  ihdr->ip_src = ihdr->ip_dst;
  ihdr->ip_dst = temp_ip_src;

  /* set icmp header */
  icmphdr->icmp_type = ICMP_ECHO_REPLY;
  icmphdr->icmp_code = DEFAULT_CODE;
  icmphdr->icmp_sum = INITIAL_SUM;
  icmphdr->icmp_sum = cksum(icmphdr, sizeof(sr_icmp_hdr_t));

  fprintf(stderr, "\nPrinting packet to be sent as icmp echo\n");
  print_hdrs(packet, len);
  sr_send_packet(sr, packet, len, interface);

  return;
}