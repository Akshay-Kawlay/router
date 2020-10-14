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
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("\n*** -> Received packet of length %d \n", len);

  /* fill in code here */

  /* Parse Ethernet Header*/
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength)
  {
    fprintf(stderr, "Failed to parse ETHERNET header, insufficient length %d\n", len);
    return;
  }

  uint16_t ethtype = ethertype(packet);
  print_hdr_eth(packet);

  if (ethtype == ethertype_ip) /* IP */
  {
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength)
    {
      fprintf(stderr, "Failed to parse IP header, insufficient length %d\n", len);
      return;
    }

    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) /* ICMP */
    {
      minlength += sizeof(sr_icmp_hdr_t);
      if (len < minlength)
      {
        fprintf(stderr, "Failed to parse ICMP header, insufficient length %d\n", len);
      }
      else
      { /* ICMP header parsed at packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) */
        print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      }
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
      print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      if (amithetarget(sr, arp_hdr->ar_tip))
      {
        if (ntohs(arp_hdr->ar_op) == arp_op_request) /* ARP Request to me */
        {
          fprintf(stderr, "ARP Request Received from address : ");
          print_addr_eth(arp_hdr->ar_sha);
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
 *---------------------------------------------------------------------*/
int amithetarget(struct sr_instance *sr, uint32_t tip)
{
  struct sr_if *if_walker = 0;

  if (sr->if_list == 0)
  {
    fprintf(stderr, "Interface list empty \n");
    return -1;
  }

  if_walker = sr->if_list;

  /*sr_print_if(if_walker);*/
  while (if_walker->next)
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

/*---------------------------------------------------------------------
 * Method: amithetarget(struct sr_instance *sr, uint32_t tip)
 * Scope:  Local
 *
 * This method is called to check if the target ip matches with router's 
 * one of the interface ips
 *---------------------------------------------------------------------*/
void setup_and_send_ARPreply(struct sr_instance *sr, uint8_t *packet /* lent */, unsigned int len)
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

/*--------------------------------------------------------------------- 
 * Method: get_interface_from_ip
 * Scope: Local
 *
 * Given an interface ip return the interface record or 0 if it doesn't
 * exist.
 *
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