// Standard libraries for input/output, integer types, and memory management
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

// DPDK libraries for environment abstraction, packet buffers, and Ethernet devices
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>



// Define constants for ring sizes and buffer sizes
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

// Default Ethernet device configuration
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mtu = RTE_ETHER_MTU, // Set the maximum transmission unit
    },
};

// Function to initialize the Ethernet port
static int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1; // Set RX and TX ring count to 1
    int retval;
    uint16_t q;

    // Check if the port ID is valid
    if (port >= rte_eth_dev_count_avail())
        return -1;

    // Configure the Ethernet device
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // Setup RX queues
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    // Setup TX queues
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    // Start the Ethernet device
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    // Enable promiscuous mode to capture all packets
    rte_eth_promiscuous_enable(port);

    return 0;
}


int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool; // Memory pool for packet buffers
    uint16_t portid = 0; // Port ID (0 in this example)

    // Initialize the Environment Abstraction Layer (EAL)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    
    // Adjust argc and argv to remove DPDK-specific arguments
    argc -= ret;
    argv += ret;

    // Create a new mempool for packet buffers
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * rte_eth_dev_count_avail(),
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize all available Ethernet ports
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
    }

    // Main processing loop
    while (1) {
        struct rte_mbuf *bufs[BURST_SIZE]; // Array to hold burst of packets
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE); // Receive packets

        // If no packets are received, continue to the next iteration
        if (unlikely(nb_rx == 0))
            continue;

        // Process each received packet
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i]; // Get the packet buffer
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *); // Get the Ethernet header

            // Check if the packet is an IPv4 packet
            if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1); // Get the IPv4 header

                // Check if the packet is a TCP packet
                if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + (ipv4_hdr->version_ihl & 0x0f) * 4); // Get the TCP header

                    // Check for SYN and SYN-ACK flags to measure round-trip time (RTT)
                    if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) {
                        if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {
                            // SYN-ACK packet received
                            uint64_t t2 = rte_rdtsc(); // Get current timestamp
                            printf("SYN-ACK received. RTT: %" PRIu64 " cycles\n", t2 - tcp_hdr->sent_seq); // Print RTT
                        } else {
                            // SYN packet sent
                            tcp_hdr->sent_seq = rte_rdtsc(); // Set the sent timestamp in the sequence number field
                            printf("SYN sent\n");
                        }
                    }
                }
            }
            rte_pktmbuf_free(m); // Free the packet buffer
        }
    }

    return 0; // Exit the program
}