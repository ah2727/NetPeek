#include "recon/persist.h"

#include <sqlite3.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "recon/graph.h"
#include "recon/evidence.h"
#include "recon_internal.h"

static np_recon_persist_state_t *g_persist = NULL;

np_recon_persist_state_t *np_recon_persist_state_create(void)
{
    return calloc(1, sizeof(np_recon_persist_state_t));
}

void np_recon_persist_state_destroy(np_recon_persist_state_t *state)
{
    if (!state)
        return;

    free(state->db_path);
    free(state);
}

const char *np_recon_default_db_path(void)
{
    static char path[1024];
    const char *home = getenv("HOME");
    if (!home || !home[0])
        home = ".";

    snprintf(path, sizeof(path), "%s/.netpeek/recon.db", home);
    return path;
}

static np_status_t np_recon_ensure_dir(void)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return NP_ERR_SYSTEM;

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/.netpeek", home);
    if (mkdir(dir, 0755) == 0)
        return NP_OK;

    if (errno == EEXIST)
        return NP_OK;

    return NP_ERR_SYSTEM;
}

static np_status_t np_exec(sqlite3 *db, const char *sql)
{
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK)
    {
        sqlite3_free(errmsg);
        return NP_ERR_SYSTEM;
    }
    return NP_OK;
}

np_status_t np_recon_persist_open(np_recon_context_t *ctx)
{
    if (!ctx)
        return NP_ERR_ARGS;

    if (!g_persist)
        g_persist = np_recon_persist_state_create();
    if (!g_persist)
        return NP_ERR_MEMORY;

    if (g_persist->open)
        return NP_OK;

    if (np_recon_ensure_dir() != NP_OK)
        return NP_ERR_SYSTEM;

    g_persist->db_path = strdup(np_recon_default_db_path());
    if (!g_persist->db_path)
        return NP_ERR_MEMORY;

    sqlite3 *db = NULL;
    if (sqlite3_open(g_persist->db_path, &db) != SQLITE_OK)
    {
        if (db)
            sqlite3_close(db);
        return NP_ERR_SYSTEM;
    }

    g_persist->sqlite = db;
    g_persist->open = true;

    const char *schema =
        "CREATE TABLE IF NOT EXISTS runs ("
        "run_id INTEGER PRIMARY KEY,"
        "start_ts INTEGER NOT NULL,"
        "end_ts INTEGER,"
        "status INTEGER,"
        "note TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS nodes ("
        "run_id INTEGER NOT NULL,"
        "node_id INTEGER NOT NULL,"
        "node_type INTEGER NOT NULL,"
        "PRIMARY KEY (run_id, node_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS edges ("
        "run_id INTEGER NOT NULL,"
        "src INTEGER NOT NULL,"
        "dst INTEGER NOT NULL,"
        "relation TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS evidence ("
        "run_id INTEGER NOT NULL,"
        "evidence_id INTEGER NOT NULL,"
        "node_id INTEGER NOT NULL,"
        "source_module TEXT,"
        "description TEXT,"
        "timestamp INTEGER,"
        "confidence REAL,"
        "PRIMARY KEY (run_id, evidence_id)"
        ");";

    return np_exec(db, schema);
}

void np_recon_persist_close(np_recon_context_t *ctx)
{
    (void)ctx;
    if (!g_persist)
        return;

    if (g_persist->open && g_persist->sqlite)
        sqlite3_close((sqlite3 *)g_persist->sqlite);

    g_persist->sqlite = NULL;
    g_persist->open = false;
    np_recon_persist_state_destroy(g_persist);
    g_persist = NULL;
}

np_status_t np_recon_persist_begin_run(np_recon_context_t *ctx)
{
    if (!ctx)
        return NP_ERR_ARGS;

    if (np_recon_persist_open(ctx) != NP_OK)
        return NP_ERR_SYSTEM;

    sqlite3 *db = (sqlite3 *)g_persist->sqlite;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT OR REPLACE INTO runs(run_id, start_ts) VALUES(?, ?)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return NP_ERR_SYSTEM;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)ctx->run_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ctx->start_ts);

    int step = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (step == SQLITE_DONE) ? NP_OK : NP_ERR_SYSTEM;
}

np_status_t np_recon_persist_flush(np_recon_context_t *ctx)
{
    if (!ctx || !g_persist || !g_persist->open)
        return NP_ERR_ARGS;

    sqlite3 *db = (sqlite3 *)g_persist->sqlite;
    np_graph_store_t *graph = (np_graph_store_t *)ctx->graph;
    np_evidence_store_t *evidence = (np_evidence_store_t *)ctx->evidence;
    if (!graph || !evidence)
        return NP_ERR_ARGS;

    if (np_exec(db, "BEGIN IMMEDIATE TRANSACTION;") != NP_OK)
        return NP_ERR_SYSTEM;

    sqlite3_stmt *node_stmt = NULL;
    sqlite3_stmt *edge_stmt = NULL;
    sqlite3_stmt *ev_stmt = NULL;

    if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO nodes(run_id,node_id,node_type) VALUES(?,?,?)", -1, &node_stmt, NULL) != SQLITE_OK)
        goto fail;
    if (sqlite3_prepare_v2(db, "INSERT INTO edges(run_id,src,dst,relation) VALUES(?,?,?,?)", -1, &edge_stmt, NULL) != SQLITE_OK)
        goto fail;
    if (sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO evidence(run_id,evidence_id,node_id,source_module,description,timestamp,confidence) VALUES(?,?,?,?,?,?,?)", -1, &ev_stmt, NULL) != SQLITE_OK)
        goto fail;

    for (size_t i = 0; i < graph->node_count; i++)
    {
        sqlite3_reset(node_stmt);
        sqlite3_bind_int64(node_stmt, 1, (sqlite3_int64)ctx->run_id);
        sqlite3_bind_int64(node_stmt, 2, (sqlite3_int64)graph->nodes[i].id);
        sqlite3_bind_int(node_stmt, 3, (int)graph->nodes[i].type);
        if (sqlite3_step(node_stmt) != SQLITE_DONE)
            goto fail;
    }

    for (size_t i = 0; i < graph->edge_count; i++)
    {
        sqlite3_reset(edge_stmt);
        sqlite3_bind_int64(edge_stmt, 1, (sqlite3_int64)ctx->run_id);
        sqlite3_bind_int64(edge_stmt, 2, (sqlite3_int64)graph->edges[i].src);
        sqlite3_bind_int64(edge_stmt, 3, (sqlite3_int64)graph->edges[i].dst);
        sqlite3_bind_text(edge_stmt, 4, graph->edges[i].relation, -1, SQLITE_STATIC);
        if (sqlite3_step(edge_stmt) != SQLITE_DONE)
            goto fail;
    }

    for (size_t i = 0; i < evidence->count; i++)
    {
        sqlite3_reset(ev_stmt);
        sqlite3_bind_int64(ev_stmt, 1, (sqlite3_int64)ctx->run_id);
        sqlite3_bind_int64(ev_stmt, 2, (sqlite3_int64)evidence->items[i].id);
        sqlite3_bind_int64(ev_stmt, 3, (sqlite3_int64)evidence->items[i].node_id);
        sqlite3_bind_text(ev_stmt, 4, evidence->items[i].source_module, -1, SQLITE_STATIC);
        sqlite3_bind_text(ev_stmt, 5, evidence->items[i].description, -1, SQLITE_STATIC);
        sqlite3_bind_int64(ev_stmt, 6, (sqlite3_int64)evidence->items[i].timestamp);
        sqlite3_bind_double(ev_stmt, 7, evidence->items[i].confidence);
        if (sqlite3_step(ev_stmt) != SQLITE_DONE)
            goto fail;
    }

    sqlite3_finalize(node_stmt);
    sqlite3_finalize(edge_stmt);
    sqlite3_finalize(ev_stmt);
    return np_exec(db, "COMMIT;");

fail:
    sqlite3_finalize(node_stmt);
    sqlite3_finalize(edge_stmt);
    sqlite3_finalize(ev_stmt);
    np_exec(db, "ROLLBACK;");
    return NP_ERR_SYSTEM;
}

np_status_t np_recon_persist_end_run(np_recon_context_t *ctx,
                                     np_status_t status,
                                     const char *note)
{
    if (!ctx || !g_persist || !g_persist->open)
        return NP_ERR_ARGS;

    sqlite3 *db = (sqlite3 *)g_persist->sqlite;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE runs SET end_ts=?, status=?, note=? WHERE run_id=?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return NP_ERR_SYSTEM;

    ctx->end_ts = time(NULL);
    {
        struct timespec ts;
#if defined(CLOCK_MONOTONIC)
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
            ctx->end_mono_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        else
#endif
            ctx->end_mono_ns = 0;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)ctx->end_ts);
    sqlite3_bind_int(stmt, 2, (int)status);
    sqlite3_bind_text(stmt, 3, note ? note : "", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)ctx->run_id);

    int step = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (step == SQLITE_DONE) ? NP_OK : NP_ERR_SYSTEM;
}
