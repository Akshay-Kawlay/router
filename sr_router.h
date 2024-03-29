/*
 * Name: Akshay Kawlay
 * Userid: kawlayak
 * File Description: 
 * 
 * */
/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ##args)
#define DebugMAC(x)                        \
  do                                       \
  {                                        \
    int ivyl;                              \
    for (ivyl = 0; ivyl < 5; ivyl++)       \
      printf("%02x:",                      \
             (unsigned char)(x[ivyl]));    \
    printf("%02x", (unsigned char)(x[5])); \
  } while (0)
#else
#define Debug(x, args...) \
  do                      \
  {                       \
  } while (0)
#define DebugMAC(x) \
  do                \
  {                 \
  } while (0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define ip_protocol_udp 17
#define ip_protocol_tcp 6
#define INITIAL_SUM 0
#define TOS_BEST_EFFORT 0
#define IP_v 4

#define BYTES_PER_ROW 4
#define ICMP_PACKET_SIZE(ihdr) (ntohs(ihdr->ip_len) - (ihdr->ip_hl * BYTES_PER_ROW))

/* ICMP types */
#define ICMP_ECHO_REPLY 0
#define ICMP_UNREACHABLE 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_TTL_EXPIRED 11

/* ICMP codes */
#define DEFAULT_CODE 0
#define ICMP_NET_UNREACHABLE 0
#define ICMP_HOST_UNREACHABLE 1
#define ICMP_PORT_UNREACHABLE 3
#define ICMP_CODE_TTL_EXPIRED 0

/* ARPcache constants */
#define SR_ARPBROADCAST_ADDR 0xFF
#define ARP_REQUEST_TIMEOUT_LIMIT 5
#define PROTOCOL_ADDR_LEN 4

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
  int sockfd;        /* socket to server */
  char user[32];     /* user name */
  char host[32];     /* host name */
  char template[30]; /* template name if any */
  unsigned short topo_id;
  struct sockaddr_in sr_addr;  /* address to server */
  struct sr_if *if_list;       /* list of interfaces */
  struct sr_rt *routing_table; /* routing table */
  struct sr_arpcache cache;    /* ARP cache */
  pthread_attr_t attr;
  FILE *logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance *sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance *, uint8_t *, unsigned int, const char *);
int sr_connect_to_server(struct sr_instance *, unsigned short, char *);
int sr_read_from_server(struct sr_instance *);

/* -- sr_router.c -- */
void sr_init(struct sr_instance *);
void sr_handlepacket(struct sr_instance *, uint8_t *, unsigned int, char *);
/* - helper functions - */
int amithetarget(struct sr_instance *sr, uint32_t tip);
void setup_and_send_arp_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len);
struct sr_if *get_interface_from_ip(struct sr_instance *sr, const uint32_t ip);
void send_icmp_ttl_expired(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void forward_ip_request(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void send_icmp_port_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void send_icmp_net_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void send_icmp_host_unreachable(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface);
struct sr_rt *sr_rt_lpm_lookup(struct sr_instance *sr, uint32_t ip);

/* -- sr_arpcache.c -- */
/* - helper functions - */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
void send_arp_request_broadcast(struct sr_instance *sr, struct sr_arpreq *req);
struct sr_if *get_interface_from_mac(struct sr_instance *sr, uint8_t *mac);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_print_if_list(struct sr_instance *);

#endif /* SR_ROUTER_H */
