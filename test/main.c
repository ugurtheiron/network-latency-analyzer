#include <stdio.h>
#include <stdlib.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define MBUF_SIZE 2048

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    struct rte_mbuf *mbufs[NUM_MBUFS];
    int ret;

    // DPDK EAL'yi başlat
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Bellek havuzu oluştur
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    printf("Memory pool created successfully.\n");

    // Bellek havuzundan mbuf'ları al
    for (int i = 0; i < NUM_MBUFS; i++) {
        mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
        if (mbufs[i] == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot allocate mbuf\n");
        }
    }

    printf("Allocated %d mbufs.\n", NUM_MBUFS);

    // mbuf'ları geri bırak
    for (int i = 0; i < NUM_MBUFS; i++) {
        rte_pktmbuf_free(mbufs[i]);
    }

    printf("Freed mbufs.\n");

    // Bellek havuzunu serbest bırak
    rte_mempool_free(mbuf_pool);
    printf("Freed memory pool.\n");

    return 0;
}
