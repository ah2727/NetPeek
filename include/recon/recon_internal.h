#ifndef NP_RECON_INTERNAL_H
#define NP_RECON_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "recon/context.h"
#include "recon/evidence.h"
#include "recon/graph.h"
#include "recon/module.h"

typedef struct {
    uint64_t id;
    np_node_type_t type;
    void *payload;
    size_t payload_size;
} np_graph_node_store_t;

typedef struct {
    uint64_t src;
    uint64_t dst;
    char relation[64];
} np_graph_edge_store_t;

typedef struct {
    np_graph_node_store_t *nodes;
    size_t node_count;
    size_t node_cap;

    np_graph_edge_store_t *edges;
    size_t edge_count;
    size_t edge_cap;

    uint64_t next_node_id;
    pthread_mutex_t lock;
} np_graph_store_t;

typedef struct {
    uint64_t id;
    uint64_t node_id;
    char source_module[64];
    char description[256];
    time_t timestamp;
    double confidence;
    void *raw_data;
} np_evidence_entry_t;

typedef struct {
    np_evidence_entry_t *items;
    size_t count;
    size_t cap;
    uint64_t next_id;
    pthread_mutex_t lock;
} np_evidence_store_t;

typedef struct {
    const np_module_t **items;
    size_t count;
    size_t cap;
    np_module_run_record_t *last_run_records;
    size_t last_run_count;
} np_module_registry_t;

typedef struct {
    void *sqlite;
    char *db_path;
    bool open;
} np_recon_persist_state_t;

np_graph_store_t *np_graph_store_create(void);
void np_graph_store_destroy(np_graph_store_t *store);

np_evidence_store_t *np_evidence_store_create(void);
void np_evidence_store_destroy(np_evidence_store_t *store);

np_module_registry_t *np_module_registry_create(void);
void np_module_registry_destroy(np_module_registry_t *registry);

np_recon_persist_state_t *np_recon_persist_state_create(void);
void np_recon_persist_state_destroy(np_recon_persist_state_t *state);

#endif
