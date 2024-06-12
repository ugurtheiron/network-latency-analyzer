#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define MBUF_SIZE 2048
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN }
};

static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count_avail())
        return -1;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    rte_eth_promiscuous_enable(port);

    return 0;
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    uint16_t portid = 0;

    uint32_t src_ip = rte_cpu_to_be_32(0xac1f1b51); // 172.31.27.81 
    uint32_t dst_ip = rte_cpu_to_be_32(0xc0a80002); // 192.168.0.2

    // Initialize the Environment Abstraction Layer (EAL)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    // argc -= ret;
    // argv += ret;

    // Create a new mempool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    } else {
        printf("mbuf created");
    }

    // Initialize all ports
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
    }

    // Main processing loop
    while (1) {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

            if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

                if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + (ipv4_hdr->version_ihl & 0x0f) * 4);

                    // Add latency measurement logic
                    uint64_t t1 = rte_rdtsc();
                    // Assuming packets with specific source/destination IP and port for simplicity
                    if (ipv4_hdr->src_addr == src_ip && tcp_hdr->src_port == rte_cpu_to_be_16(2222)) {
                        // Capture the SYNC message
                    } else if (ipv4_hdr->src_addr == dst_ip && tcp_hdr->src_port == rte_cpu_to_be_16(2222)) {
                        // Capture the SYNC-ACK message and calculate time difference
                        uint64_t t2 = rte_rdtsc();
                        uint64_t latency = t2 - t1;
                        printf("Latency: %"PRIu64" cycles\n", latency);
                    }
                }
            }
            rte_pktmbuf_free(m);
        }
    }

    return 0;
}
