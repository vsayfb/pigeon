#ifndef PIGEON_TUI_MODEL_H
#define PIGEON_TUI_MODEL_H

#include "flow/flow_key.h"
#include "flow/flow_table.h"

#define TUI_MAX_ROWS 200
#define TUI_HISTORY 60
#define TUI_ERROR_LEN 256
#define TUI_SEARCH_LEN 128

enum tui_sort { TUI_SORT_TOTAL, TUI_SORT_DOWNLOAD, TUI_SORT_UPLOAD };

struct tui_options {
    char search[TUI_SEARCH_LEN];
    int protocol;              /* 0, 6 or 17 */
    int family;                /* 0, 4 or 6 */
    int recent_seconds;        /* zero means all recorded */
    enum tui_sort sort;
    int application_selected;  /* distinguishes all apps from unresolved (empty name) */
    char application[FLOW_APP_LEN];
};

struct tui_conversation {
    struct flow_key key;
    struct flow_delta totals;
    char name[254];
};

struct tui_endpoint {
    struct ip_addr ip;
    char name[254];
    int64_t first_seen;
    int64_t last_seen;
};

struct tui_application {
    char name[FLOW_APP_LEN];
    double bytes_down;
    double bytes_up;
    uint64_t conversations;
    uint64_t remote_ips;
    int64_t last_seen;
};

struct tui_sample {
    double down;
    double up;
    double seconds;
};

struct tui_snapshot {
    struct tui_conversation live[TUI_MAX_ROWS];
    struct tui_conversation top[TUI_MAX_ROWS];
    struct tui_endpoint endpoints[TUI_MAX_ROWS];
    struct tui_application applications[TUI_MAX_ROWS];
    size_t live_count;
    size_t top_count;
    size_t endpoint_count;
    size_t application_count;

    uint64_t conversations;
    uint64_t remote_ips;
    double bytes_down;
    double bytes_up;
    int64_t latest_packet;
    int64_t loaded_at;
    int has_packets;

    double rate_down;
    double rate_up;
    int rates_valid;
    struct tui_sample history[TUI_HISTORY];
    size_t history_count;
};

struct tui_reader;

/* Opens an existing schema-v4 database read-only. Never creates or migrates
 * the database. Caller owns the reader and closes it with tui_reader_close().
 * Returns the reader, or NULL with a TUI_ERROR_LEN-byte error explanation. */
struct tui_reader *tui_reader_open(const char *path, char error[TUI_ERROR_LEN]);

void tui_reader_close(struct tui_reader *reader);

/* Reads all panels in one short snapshot transaction. now is Unix seconds;
 * monotonic_seconds measures elapsed viewer time. Lists contain at most
 * TUI_MAX_ROWS matches. Search matches name/IP/application on conversation
 * lists, name/IP on endpoints. Rankings are cumulative; recent_seconds applies only
 * to Live Traffic. Protocol filtering applies to conversation lists; endpoint
 * first-seen times always span the complete database. Exact application
 * selection filters only conversations. Overview and Applications are unfiltered;
 * Applications groups all stored rows before ranking (not just the top 200).
 * Rates are estimated from database counter deltas, not packet timestamps.
 * Returns 0 on success or -1 with error set, leaving out and rate history
 * unchanged. No returned data borrows SQLite memory. */
int tui_reader_refresh(struct tui_reader *reader, const struct tui_options *options,
                        int64_t now, double monotonic_seconds, struct tui_snapshot *out,
                        char error[TUI_ERROR_LEN]);

#endif
