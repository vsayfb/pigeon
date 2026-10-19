#include "tui/model.h"
#include "tui/screen.h"

#include <curses.h>
#include <inttypes.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void on_signal(int signal_number) {
    (void)signal_number;

    stopping = 1;
}

static double monotonic_now(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        return -1;
    }

    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static void print_safe(const char *text) {
    for (size_t i = 0; text[i] != '\0'; i++) {
        const unsigned char byte = (unsigned char)text[i];

        putchar(byte >= 32 && byte <= 126 ? byte : '?');
    }
}

static void print_row(const struct tui_conversation *row) {
    char remote[IP_ADDR_STR_LEN];

    print_safe(row->key.application[0] ? row->key.application : "unresolved");
    printf("  %s%s%s:%u %s down=%" PRIu64 " up=%" PRIu64 " name=",
           row->key.remote_ip.family == 6 ? "[" : "",
           ip_addr_str(&row->key.remote_ip, remote), row->key.remote_ip.family == 6 ? "]" : "",
           row->key.remote_port, row->key.protocol == 6 ? "TCP" : "UDP",
           row->totals.bytes_in, row->totals.bytes_out);
    print_safe(row->name[0] ? row->name : "-");
    putchar('\n');
}

static void print_snapshot(const struct tui_snapshot *snapshot) {
    printf("Traffic overview (all recorded payload)\nconversations=%" PRIu64
           " remote_ips=%" PRIu64 " down=%.0f up=%.0f\n",
           snapshot->conversations, snapshot->remote_ips, snapshot->bytes_down, snapshot->bytes_up);
    puts("Live traffic (last 30 seconds; counters are totals)");

    for (size_t i = 0; i < snapshot->live_count; i++) {
        print_row(&snapshot->live[i]);
    }

    puts("Top Conversations (all recorded; total traffic)");

    for (size_t i = 0; i < snapshot->top_count; i++) {
        print_row(&snapshot->top[i]);
    }

    puts("Applications (all recorded; total traffic)");

    for (size_t i = 0; i < snapshot->application_count; i++) {
        const struct tui_application *row = &snapshot->applications[i];

        print_safe(row->name[0] ? row->name : "unresolved");
        printf(" down=%.0f up=%.0f conversations=%" PRIu64 " remote_ips=%" PRIu64 "\n",
               row->bytes_down, row->bytes_up, row->conversations, row->remote_ips);
    }

    puts("New endpoints (database first seen)");

    for (size_t i = 0; i < snapshot->endpoint_count; i++) {
        char address[IP_ADDR_STR_LEN];

        printf("%s first_seen=%" PRId64 " name=",
               ip_addr_str(&snapshot->endpoints[i].ip, address), snapshot->endpoints[i].first_seen);
        print_safe(snapshot->endpoints[i].name[0] ? snapshot->endpoints[i].name : "-");
        putchar('\n');
    }
}

static int run_screen(struct tui_reader *reader, struct tui_snapshot *snapshot,
                       struct tui_snapshot *next, const char *path) {
    SCREEN *terminal = newterm(NULL, stdout, stdin);

    if (terminal == NULL) {
        fprintf(stderr, "cannot initialize terminal; check TERM\n");

        return 1;
    }

    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    wtimeout(stdscr, 100);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_CYAN, -1);
        init_pair(2, COLOR_GREEN, -1);
        init_pair(3, COLOR_YELLOW, -1);
    }

    struct sigaction action = { .sa_handler = on_signal };
    struct sigaction previous_int;
    struct sigaction previous_term;

    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, &previous_int) == -1) {
        endwin();
        delscreen(terminal);
        perror("viewer signal setup");

        return 1;
    }

    if (sigaction(SIGTERM, &action, &previous_term) == -1) {
        sigaction(SIGINT, &previous_int, NULL);
        endwin();
        delscreen(terminal);
        perror("viewer signal setup");

        return 1;
    }

    struct tui_options options = { .recent_seconds = 30 };
    struct tui_screen state = { 0 };
    char error[TUI_ERROR_LEN] = "";
    double next_refresh = 0;
    int forced_refresh = 1;
    int result = 0;

    while (!stopping) {
        const double monotonic = monotonic_now();
        const time_t wall = time(NULL);

        if (monotonic < 0 || wall == (time_t)-1) {
            result = 1;
            break;
        }

        if (forced_refresh || (!state.paused && monotonic >= next_refresh)) {
            char query_error[TUI_ERROR_LEN];

            if (tui_reader_refresh(reader, &options, (int64_t)wall, monotonic, next, query_error) == 0) {
                tui_screen_reselect(snapshot, next, &state);
                *snapshot = *next;
                error[0] = '\0';
            } else {
                snprintf(error, sizeof error, "STALE: %.240s", query_error);
            }

            next_refresh = monotonic + 1;
            forced_refresh = 0;
        }

        tui_screen_draw(snapshot, &options, &state, path, error, (int64_t)wall);

        const int key = wgetch(stdscr);
        const int action_flags = tui_screen_key(key, snapshot, &options, &state);

        if (action_flags & TUI_KEY_QUIT) {
            break;
        }

        if (action_flags & TUI_KEY_REFRESH) {
            forced_refresh = 1;
        }
    }

    endwin();
    delscreen(terminal);
    sigaction(SIGINT, &previous_int, NULL);
    sigaction(SIGTERM, &previous_term, NULL);

    return result;
}

int main(int argc, char **argv) {
    const char *path = "pigeon.db";
    int once = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--once") == 0) {
            once = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [--db <path>] [--once]\n", argv[0]);

            return 0;
        } else {
            fprintf(stderr, "usage: %s [--db <path>] [--once]\n", argv[0]);

            return 2;
        }
    }

    if (!once && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
        fprintf(stderr, "pigeon-tui requires a terminal; use --once for a text snapshot\n");

        return 2;
    }

    char error[TUI_ERROR_LEN] = "clock unavailable";
    struct tui_reader *reader = tui_reader_open(path, error);

    if (reader == NULL) {
        fprintf(stderr, "%s\n", error);

        return 1;
    }

    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_snapshot *next = calloc(1, sizeof *next);

    if (snapshot == NULL || next == NULL) {
        free(snapshot);
        free(next);
        tui_reader_close(reader);
        fprintf(stderr, "snapshot allocation failed\n");

        return 1;
    }

    int result;

    if (once) {
        const struct tui_options options = { .recent_seconds = 30 };
        const time_t now = time(NULL);
        const double monotonic = monotonic_now();

        snprintf(error, sizeof error, "clock unavailable");

        if (now == (time_t)-1 || monotonic < 0 ||
            tui_reader_refresh(reader, &options, (int64_t)now, monotonic, snapshot, error) == -1) {
            fprintf(stderr, "snapshot failed: %s\n", error);
            result = 1;
        } else {
            print_snapshot(snapshot);
            result = 0;
        }
    } else {
        setlocale(LC_ALL, "");
        result = run_screen(reader, snapshot, next, path);
    }

    free(snapshot);
    free(next);
    tui_reader_close(reader);

    return result;
}
