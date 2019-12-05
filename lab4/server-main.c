#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>


#include <stdbool.h>
#include <inttypes.h>
#include <signal.h>

#include "SimpleDNS.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = 0x38d34,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	}
};
struct rte_mempool *mbuf_pool;
//struct rte_mbuf *query_buf[BURST_SIZE];
//struct rte_mbuf *reply_buf[BURST_SIZE];
static volatile bool force_quit;
uint8_t per_lcore_pkt=0;
struct statistics {
	uint64_t tx;
	uint64_t rx;
} __rte_cache_aligned;
struct statistics pkts[RTE_MAX_ETHPORTS];

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 4, tx_rings = 4;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;

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
	
	rxconf = dev_info.default_rxconf;
	rxconf.offloads = port_conf.rxmode.offloads;
	/* Allocate and set up RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), NULL);
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

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

/*
 * In this function we complete the headers of a answer packet(buf1), 
 * basing on information from the query packet(buf2).
 */
static void
build_packet(char *buf1, char * buf2, uint16_t pkt_size)
{
	struct ether_hdr *eth_hdr1, *eth_hdr2;
	struct ipv4_hdr *ip_hdr1, *ip_hdr2;
	struct udp_hdr *udp_hdr1, *udp_hdr2;

	eth_hdr1 = (struct ether_hdr *)buf1;
	ip_hdr1 = (struct ipv4_hdr *)(eth_hdr1 + 1);
	udp_hdr1 = (struct udp_hdr *)(ip_hdr1 + 1);

	eth_hdr2 = (struct ether_hdr *)buf2;
	ip_hdr2 = (struct ipv4_hdr *)(eth_hdr2 + 1);
	udp_hdr2 = (struct udp_hdr *)(ip_hdr2 + 1);
	
	//struct ether_addr s_addr,d_addr;
	ether_addr_copy(&eth_hdr1->d_addr, &eth_hdr2->s_addr);
	ether_addr_copy(&eth_hdr1->s_addr, &eth_hdr2->d_addr);
	eth_hdr2->ether_type = htons(ETHER_TYPE_IPv4);

	ip_hdr2->version_ihl = (4<<4) + (sizeof(struct ipv4_hdr)>>2);
	ip_hdr2->type_of_service = 0;
	//printf("pkt_size:%d\n",pkt_size);
	ip_hdr2->total_length = htons(pkt_size - sizeof(struct ether_hdr));
	ip_hdr2->packet_id = ip_hdr1->packet_id;
	ip_hdr2->fragment_offset = ip_hdr1->fragment_offset;
	ip_hdr2->time_to_live = 255;
	ip_hdr2->next_proto_id = IPPROTO_UDP;
	ip_hdr2->hdr_checksum = 0;
	rte_memcpy(&ip_hdr2->src_addr, &ip_hdr1->dst_addr, 4);
	rte_memcpy(&ip_hdr2->dst_addr, &ip_hdr1->src_addr, 4);

	udp_hdr2->src_port = udp_hdr1->dst_port;
	udp_hdr2->dst_port = udp_hdr1->src_port;
	udp_hdr2->dgram_len = htons(pkt_size - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr));;
	udp_hdr2->dgram_cksum = 0;
	ip_hdr2->hdr_checksum = rte_ipv4_cksum(ip_hdr2);
	udp_hdr2->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr2,udp_hdr2);
	/*
	printf("buf1:\n");
	int size=sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)+sizeof(struct udp_hdr);
	int i=0;
	for (i=0;i<size;i++) {
		if (i==0)
			printf("\nether:\n");
		if (i==sizeof(struct ether_hdr))
			printf("\nip:\n");
		if (i==sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr))
			printf("\nudp:\n");
		printf("%02X ",(unsigned char)buf1[i]);
	}
	*/
	/*
	printf("\n");
	for (i=0;i<size;i++) {
		printf("%d ",sizeof(buf1[i]));
	}
	*/
	/*
	printf("\n");
	printf("buf2:\n");
	for (i=0;i<size;i++) {
		if (i==0)
			printf("\nether:\n");
		if (i==sizeof(struct ether_hdr))
			printf("\nip:\n");
		if (i==sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr))
			printf("\nudp:\n");
		printf("%02X ",(unsigned char)buf2[i]);
	}
	*/
	//Add your code here.
	//Part 4.
	
	
	

}

void msg_produce(uint16_t port)
{
	struct rte_mbuf *query_buf[BURST_SIZE];
 	struct rte_mbuf *reply_buf[BURST_SIZE]; 
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp_hdr;
	struct Message msg;
	memset(&msg, 0, sizeof(struct Message));
	uint16_t i,sends=0;
	uint8_t *buffer, *buf;
	uint8_t *pkt;
	int nbytes;
	unsigned lcore_id;
	unsigned queue_id;
	lcore_id = rte_lcore_id();
	queue_id = lcore_id/4;
	for (i = 0; i < BURST_SIZE; i++)
	{
		do {
			reply_buf[i] = rte_pktmbuf_alloc(mbuf_pool);
		} while (unlikely(reply_buf[i] == NULL));
	}
	//printf("In %d, offset = %d ,nb_rx= %d \n",lcore_id, offset, nb_rx);
	//printf("123344,%d\n",nb_rx);
	while (! force_quit) {
	const uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, query_buf, BURST_SIZE);
	if (likely(nb_rx == 0)) {
		continue;
	}
	sends = 0;
	for (i = 0; i < nb_rx; i++)
	{
		free_questions(msg.questions);
		free_resource_records(msg.answers);
		free_resource_records(msg.authorities);
		free_resource_records(msg.additionals);
		memset(&msg, 0, sizeof(struct Message));
		pkt = rte_pktmbuf_mtod(query_buf[i], uint8_t*);
		eth_hdr = (struct ether_hdr *)pkt;
		ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
		buffer = (uint8_t *)(udp_hdr + 1);
		nbytes = rte_pktmbuf_data_len(query_buf[i]) - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr) - sizeof(struct udp_hdr);
		
		//printf("%s,!!!!,%d\n",buffer, nbytes);
		//rte_pktmbuf_free(query_buf);
		//Add your code here.
		//Part 1.
//		do {
//			reply_buf[i] = rte_pktmbuf_alloc(mbuf_pool);
//		} while (unlikely(reply_buf[i] == NULL));
		reply_buf[i]->pkt_len = 0;
		if (eth_hdr->ether_type!=htons(ETHER_TYPE_IPv4) || 
		ip_hdr->next_proto_id!=IPPROTO_UDP ||
		udp_hdr->dst_port!=htons(9000)) {
			continue;
		}
		
		/*********read input (begin)**********/
		if (decode_msg(&msg, buffer, nbytes) != 0) {
			//printf("no\n");			
			continue;
		}
		/* Print query */
		//printf("1\n");
		//print_query(&msg);
		//printf("2\n");
		resolver_process(&msg);
		//printf("3\n");
		/* Print response */
		//print_query(&msg);
		//printf("Total DNS: %d\n",count);
		/*********read input (end)**********/
		//printf("4\n");

		//Add your code here.
		//Part 2.
		
		
		
		/*********write output (begin)**********/
		uint8_t *p = buffer;
		if (encode_msg(&msg, &p) != 0) {
			continue;
		}

		uint32_t buflen = p - buffer;
		/*********write output (end)**********/
		
		uint16_t pkt_size=sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + buflen;

/*		do {
			reply_buf[sends] = rte_pktmbuf_alloc(mbuf_pool); 		
		} while (unlikely(reply_buf[sends]==NULL));
*/
		reply_buf[sends]->nb_segs = 1;
		reply_buf[sends]->next = NULL;
		reply_buf[sends]->pkt_len = pkt_size;
		reply_buf[sends]->data_len = pkt_size;

		pkt = rte_pktmbuf_mtod(reply_buf[sends], uint8_t*);
		eth_hdr = (struct ether_hdr *)pkt;
		ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
		buf = (uint8_t *)(udp_hdr + 1);
		rte_memcpy(buf, buffer, buflen);		

		build_packet(rte_pktmbuf_mtod(query_buf[i], void *), rte_pktmbuf_mtod(reply_buf[sends], void *), pkt_size);
		sends += 1;
		/*
		uint16_t ret;
		ret = rte_eth_tx_burst(0, 0, &reply_buf, sends);
		if (likely(ret == 0)) {
			rte_pktmbuf_free(reply_buf);
		}*/
	}
	pkts[lcore_id].rx += nb_rx;
	pkts[lcore_id].tx += sends;
/*	for (i = 0; i < nb_rx; i++)
	{
		rte_pktmbuf_free(query_buf[i]);
	}
*/	//printf("RTE_MAX_ETHERPORTS=%d\n",RTE_MAX_ETHPORTS);
	uint16_t ret;
		
	ret = rte_eth_tx_burst(port, queue_id, reply_buf, BURST_SIZE);
	/* Free unsent packet. */
	//printf("Send %d packets, total: %d ,recv: %d\n",ret,sends,nb_rx);	
/*	if (likely(ret < sends)) {
		uint16_t j;
		for (j = ret; j < sends; j++)
			rte_pktmbuf_free(reply_buf[j]);
	}
*/
}
	for (i = 0; i < BURST_SIZE; i++)
	{
		rte_pktmbuf_free(reply_buf[i]);
		rte_pktmbuf_free(query_buf[i]);
	}
}


void send_main(uint16_t port)
{
	//struct rte_mbuf *query_buf, *reply_buf;
	uint16_t lcore_id;	
	/* Run until the application is quit or killed. */
//	while (!force_quit) {
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(msg_produce, port, lcore_id);
	}
	msg_produce(port);
	rte_eal_mp_wait_lcore();		
		
//	}
}
/*
 * The lcore main. This is the main thread that does the work, read
 * an query packet and write an reply packet.
 */

static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port = 0;	//only one port is used.
	uint8_t query_buf_flag = 0;		//set to 1 after query packet received.	
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
					(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);
	
	printf("\nSimpleDNS (using DPDK) is running...\n");
	send_main(port);
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	uint16_t portid = 0, nb_ports = 1;
	uint32_t total_tx = 0, total_rx = 0;
	unsigned lcore_id;
	int i;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port 0. */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	if (rte_eth_dev_socket_id(portid) > 0 &&
			rte_eth_dev_socket_id(portid) !=
					(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", portid);

	memset(&pkts, 0, sizeof(pkts));
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	
	printf("\nSimpleDNS (using DPDK) is running...\n");
	send_main(portid);
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		total_rx += pkts[i].rx;
		total_tx += pkts[i].tx;
	}
	printf("\nTotal RX: %d, Total TX: %d\n", total_tx, total_tx);
	return 0;
}
