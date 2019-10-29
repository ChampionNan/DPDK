/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

struct rte_mempool *mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}


static bool
build_udp_packet(char *buf, int *pkt_size)
{
	//若使用 DPDK 的协议头结构体，此处结构体名需对应修改
	struct ether_hdr *eh = (struct ether_hdr *)buf;
	struct ether_addr d_addr;
	struct ipv4_hdr *ip = (struct ipv4_hdr *)(eh + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	char *payload = (char *)(udp + 1);
	
	/*add your code here*/
	rte_eth_macaddr_get(0, &d_addr);
	ether_addr_copy(&d_addr, &eh->d_addr);
	ether_addr_copy(&d_addr, &eh->s_addr);	
	eh->ether_type = htons(ETHER_TYPE_IPv4);

	ip->version_ihl = (IPVERSION<<4) + (sizeof(struct ipv4_hdr)>>2);
	ip->type_of_service = 0;
	ip->total_length = htons(*(pkt_size) - sizeof(struct ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 2;
	ip->next_proto_id = IPPROTO_UDP;
	ip->hdr_checksum = 0;	
	ip->src_addr = inet_addr("127.0.0.1");
	ip->dst_addr = inet_addr("127.0.0.2");

	uint16_t tmp=2000;
	udp->uh_sport = htons(tmp);
	udp->uh_dport = htons(tmp);
	udp->uh_ulen = htons(*(pkt_size) - sizeof(struct ether_hdr) - sizeof(struct ip));
	udp->uh_sum = 0;
	udp->uh_sum = rte_ipv4_udptcp_cksum(ip,udp);
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	*(payload +  0) = 'h';
	*(payload +  1) = 'e';
	*(payload +  2) = 'l';
	*(payload +  3) = 'l';
	*(payload +  4) = 'o';
	*(payload +  5) = ',';
	*(payload +  6) = ' ';
	*(payload +  7) = 'w';
	*(payload +  8) = 'o';
	*(payload +  9) = 'r';
	*(payload + 10) = 'l';
	*(payload + 11) = 'd';
	*(payload + 12) = '.';
	*(payload + 13) = '\0';

	return (true);
}

/*
 * The lcore main. This is the main thread that does the work, construct a
 * packet and deliver it.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u is running. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		int ret;
		int32_t pkt_size = 60;  //为简单起见，这里直接设为一个固定值，也可以改
                                //为由 build_udp_packet 函数返回实际数据包大小
		struct rte_mbuf *worker;
		
		do {
			worker = rte_pktmbuf_alloc(mbuf_pool);
		} while (unlikely(worker == NULL));
		worker->nb_segs = 1;
		worker->next = NULL;
		worker->pkt_len = pkt_size;
		worker->data_len = pkt_size;
		build_udp_packet(rte_pktmbuf_mtod(worker, void *), &pkt_size);
		
		ret = rte_eth_tx_burst(0, 0, &worker, 1);
		
		/* Free unsent packet. */
		if (unlikely(ret < 1)) {
			rte_pktmbuf_free(worker);
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
