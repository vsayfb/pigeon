#include "tui/screen.h"

#include <curses.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct panel {
    int y;
    int x;
    int height;
    int width;
};

static void text(int y, int x, int width, int attributes, const char *format, ...)
    __attribute__((format(printf, 5, 6)));

static void text(int y, int x, int width, int attributes, const char *format, ...) {
    if (y < 0 || y >= LINES || x < 0 || x >= COLS || width <= 0) {
        return;
    }

    char buffer[1024];
    va_list args;

    va_start(args, format);
    vsnprintf(buffer, sizeof buffer, format, args);
    va_end(args);

    for (size_t i = 0; buffer[i] != '\0'; i++) {
        if ((unsigned char)buffer[i] < 32 || (unsigned char)buffer[i] > 126) {
            buffer[i] = '?';
        }
    }

    if (width > COLS - x) {
        width = COLS - x;
    }

    attron(attributes);
    mvaddnstr(y, x, buffer, width);
    attroff(attributes);
}

static void draw_border(struct panel p, const char *title, int focused) {
    mvhline(p.y, p.x + 1, ACS_HLINE, p.width - 2);
    mvhline(p.y + p.height - 1, p.x + 1, ACS_HLINE, p.width - 2);
    mvvline(p.y + 1, p.x, ACS_VLINE, p.height - 2);
    mvvline(p.y + 1, p.x + p.width - 1, ACS_VLINE, p.height - 2);
    mvaddch(p.y, p.x, ACS_ULCORNER);
    mvaddch(p.y, p.x + p.width - 1, ACS_URCORNER);
    mvaddch(p.y + p.height - 1, p.x, ACS_LLCORNER);
    mvaddch(p.y + p.height - 1, p.x + p.width - 1, ACS_LRCORNER);

    text(p.y, p.x + 2, p.width - 4, A_BOLD | (focused ? COLOR_PAIR(1) : 0), " %s ", title);
}

static void bytes(double value, char out[20]) {
    const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
    size_t unit = 0;

    while (value >= 1024 && unit < 6) {
        value /= 1024;
        unit++;
    }

    snprintf(out, 20, unit == 0 ? "%.0f %s" : "%.1f %s", value, units[unit]);
}

static void age(int64_t now, int64_t then, char out[32]) {
    const long double seconds = (long double)now - (long double)then;

    if (seconds < 0) {
        snprintf(out, 32, "future");
    } else if (seconds < 60) {
        snprintf(out, 32, "%.0Lfs", seconds);
    } else if (seconds < 3600) {
        snprintf(out, 32, "%.0Lfm", seconds / 60);
    } else if (seconds < 86400) {
        snprintf(out, 32, "%.0Lfh", seconds / 3600);
    } else {
        snprintf(out, 32, "%.0Lfd", seconds / 86400);
    }
}

static void timestamp(int64_t value, char out[40]) {
    const time_t time_value = (time_t)value;
    struct tm local;

    if ((int64_t)time_value == value && localtime_r(&time_value, &local) != NULL &&
        strftime(out, 40, "%Y-%m-%d %H:%M:%S", &local) != 0) {
        return;
    }

    snprintf(out, 40, "%" PRId64, value);
}

static size_t panel_count(const struct tui_snapshot *snapshot, int focus) {
    return focus == 0 ? snapshot->live_count : focus == 1 ? snapshot->top_count
                                                       : snapshot->endpoint_count;
}

static void overview(struct panel p, const struct tui_snapshot *snapshot, int64_t now) {
    draw_border(p, "Traffic overview | all recorded payload", 0);

    char down[20];
    char up[20];
    char latest[32];

    bytes(snapshot->bytes_down, down);
    bytes(snapshot->bytes_up, up);
    age(now, snapshot->latest_packet, latest);
    text(p.y + 1, p.x + 2, p.width - 4, 0,
         "Totals: Down %s  Up %s   Conversations %" PRIu64 "   Remote IPs %" PRIu64,
         down, up, snapshot->conversations, snapshot->remote_ips);

    if (snapshot->rates_valid) {
        bytes(snapshot->rate_down, down);
        bytes(snapshot->rate_up, up);
        text(p.y + 2, p.x + 2, p.width - 4, COLOR_PAIR(2),
             "DB delta rate: Down %s/s  Up %s/s   Latest packet: %s ago", down, up,
             snapshot->has_packets ? latest : "none");
    } else {
        text(p.y + 2, p.x + 2, p.width - 4, A_DIM,
             "DB delta rate: waiting for next sample   Latest packet: %s",
             snapshot->has_packets ? latest : "none");
    }

    const size_t capacity = (size_t)(p.width - 38) < TUI_HISTORY ? (size_t)(p.width - 38) : TUI_HISTORY;
    const size_t count = snapshot->history_count < capacity ? snapshot->history_count : capacity;
    const size_t start = snapshot->history_count - count;
    double peak = 0;
    double seconds = 0;
    const char *levels = "_.:-=+*#%@";

    for (size_t i = start; i < snapshot->history_count; i++) {
        const struct tui_sample *sample = &snapshot->history[i];

        if (sample->down > peak) {
            peak = sample->down;
        }

        if (sample->up > peak) {
            peak = sample->up;
        }

        seconds += sample->seconds;
    }

    char scale[20];

    bytes(peak, scale);

    for (int direction = 0; direction < 2; direction++) {
        char graph[TUI_HISTORY + 1];

        memset(graph, ' ', capacity);

        for (size_t i = 0; i < count; i++) {
            const struct tui_sample *sample = &snapshot->history[start + i];
            const double value = direction == 0 ? sample->down : sample->up;
            unsigned level = peak == 0 ? 0 : (unsigned)(value / peak * 9);

            if (value > 0 && level == 0) {
                level = 1;
            }

            graph[capacity - count + i] = levels[level > 9 ? 9 : level];
        }

        graph[capacity] = '\0';

        text(p.y + 3 + direction, p.x + 2, p.width - 4, A_BOLD | COLOR_PAIR(direction == 0 ? 1 : 2),
             "%s [%s] %.0fs | 0..%s/s", direction == 0 ? "Down" : "Up  ", graph, seconds, scale);
    }
}

static void conversation_panel(struct panel p, const struct tui_snapshot *snapshot,
                                 const struct tui_options *options, const struct tui_screen *state,
                                 int focus, int64_t now) {
    const int live = focus == 0;
    const char *sorts[] = { "total", "download", "upload" };
    char title[100];

    if (live) {
        if (options->recent_seconds == 0) {
            snprintf(title, sizeof title, "Live traffic | all recorded by recency");
        } else {
            snprintf(title, sizeof title, "Live traffic | last %ds", options->recent_seconds);
        }
    } else {
        snprintf(title, sizeof title, "Top Conversations | all recorded | %s", sorts[options->sort]);
    }

    draw_border(p, title, state->focus == focus);

    const int application_width = p.width >= 80 ? 18 : 12;
    const int endpoint_width = p.width - (live ? 24 : 26) - application_width - 1;
    const struct tui_conversation *rows = live ? snapshot->live : snapshot->top;
    const size_t count = live ? snapshot->live_count : snapshot->top_count;
    const int visible = p.height - 4;
    const size_t selected = state->selected[focus];
    const size_t start = selected >= (size_t)visible ? selected - (size_t)visible + 1 : 0;

    text(p.y + 1, p.x + 1, p.width - 2, A_DIM,
         live ? "  %-*s %-*s Proto  Port   Seen" : "  %-*s %-*s       Down         Up",
         application_width, "Application", endpoint_width, "Endpoint");

    for (int i = 0; i < visible && start + (size_t)i < count; i++) {
        const size_t index = start + (size_t)i;
        const struct tui_conversation *row = &rows[index];
        char address[IP_ADDR_STR_LEN];
        char label[384];
        char last[32];
        char down[20];
        char up[20];

        ip_addr_str(&row->key.remote_ip, address);

        if (live) {
            snprintf(label, sizeof label, "%s%s%s", row->name,
                     row->name[0] ? " -> " : "", address);
        } else {
            snprintf(label, sizeof label, "%s%s%s%s%s:%u/%s", row->name,
                     row->name[0] ? " -> " : "", row->key.remote_ip.family == 6 ? "[" : "",
                     address, row->key.remote_ip.family == 6 ? "]" : "",
                     row->key.remote_port, row->key.protocol == 6 ? "tcp" : "udp");
        }

        age(now, row->totals.last_seen, last);
        bytes((double)row->totals.bytes_in, down);
        bytes((double)row->totals.bytes_out, up);

        const int attributes = state->focus == focus && selected == index ? A_REVERSE : 0;

        if (live) {
            text(p.y + 2 + i, p.x + 1, p.width - 2, attributes,
                 "%c %-*.*s %-*.*s %3s %5u %6.6s", selected == index ? '>' : ' ',
                 application_width, application_width, row->key.application[0] ? row->key.application : "unresolved",
                 endpoint_width, endpoint_width, label, row->key.protocol == 6 ? "TCP" : "UDP",
                 row->key.remote_port, last);
        } else {
            text(p.y + 2 + i, p.x + 1, p.width - 2, attributes,
                 "%c %-*.*s %-*.*s %10.10s %10.10s", selected == index ? '>' : ' ',
                 application_width, application_width, row->key.application[0] ? row->key.application : "unresolved",
                 endpoint_width, endpoint_width, label, down, up);
        }
    }

    if (count == 0) {
        text(p.y + 2, p.x + 2, p.width - 4, A_DIM, "No matching conversations");
    }

    text(p.y + p.height - 2, p.x + 2, p.width - 4, A_DIM,
         "%zu shown (limit %d) | Enter: details", count, TUI_MAX_ROWS);
}

static void endpoint_panel(struct panel p, const struct tui_snapshot *snapshot,
                            const struct tui_screen *state) {
    draw_border(p, "New endpoints | first seen in this database", state->focus == 2);

    const int visible = p.height - 3;
    const size_t selected = state->selected[2];
    const size_t start = selected >= (size_t)visible ? selected - (size_t)visible + 1 : 0;

    for (int i = 0; i < visible && start + (size_t)i < snapshot->endpoint_count; i++) {
        const size_t index = start + (size_t)i;
        const struct tui_endpoint *row = &snapshot->endpoints[index];
        char address[IP_ADDR_STR_LEN];
        char first[40];

        ip_addr_str(&row->ip, address);
        timestamp(row->first_seen, first);
        text(p.y + 1 + i, p.x + 1, p.width - 2,
             state->focus == 2 && selected == index ? A_REVERSE : 0,
             "%c %.19s  %s%s%s", selected == index ? '>' : ' ', first, row->name,
             row->name[0] != '\0' ? " -> " : "", address);
    }

    if (snapshot->endpoint_count == 0) {
        text(p.y + 1, p.x + 2, p.width - 4, A_DIM, "No matching endpoints");
    }

    text(p.y + p.height - 2, p.x + 2, p.width - 4, A_DIM,
         "%zu remote IPs shown (limit %d); protocol filter does not apply", snapshot->endpoint_count, TUI_MAX_ROWS);
}

static void modal(const struct tui_snapshot *snapshot, const struct tui_screen *state) {
    const int width = COLS < 104 ? COLS - 4 : 100;
    const int height = LINES < 23 ? LINES - 4 : 19;
    struct panel p = { (LINES - height) / 2, (COLS - width) / 2, height, width };

    for (int y = p.y; y < p.y + p.height; y++) {
        mvhline(y, p.x, ' ', p.width);
    }

    draw_border(p, state->help ? "Help" : "Selected endpoint", 1);

    char content[16][320] = { { 0 } };
    size_t count = 0;

    if (state->help) {
        const char *lines[] = {
            "Tab / Shift-Tab  Change focused panel", "Up/Down, j/k     Select row; PgUp/PgDn, Home/End also work",
            "Enter           Open details; Enter/Esc closes", "/               Search name, remote IP, or application (conversations)",
            "s               Sort Top Conversations: total/down/up", "r               Live window: 10s / 30s / 120s / all",
            "f               Conversation protocol: any / TCP / UDP", "v               Address family: any / IPv4 / IPv6",
            "p               Pause auto-refresh; collector keeps running", "q / Ctrl-C      Quit viewer; collector keeps running",
            "Rates are database counter deltas, not NIC speed.", "Totals count transport payload, including retransmissions.",
            "Graphs: old -> new, shared scale; _ is zero, @ is peak.", "No collector heartbeat is stored. Idle is not stopped.",
            "New endpoints group remote IPs across ports/local IPs.", "Names are recorded DNS associations, not service proof."
        };

        count = sizeof lines / sizeof lines[0];

        for (size_t i = 0; i < count; i++) {
            snprintf(content[i], sizeof content[i], "%s", lines[i]);
        }
    } else if (panel_count(snapshot, state->focus) != 0) {
        const size_t index = state->selected[state->focus];
        char address[IP_ADDR_STR_LEN];
        char first[40];
        char last[40];

        if (state->focus == 2) {
            const struct tui_endpoint *row = &snapshot->endpoints[index];

            timestamp(row->first_seen, first);
            timestamp(row->last_seen, last);
            snprintf(content[count++], 320, "%s", row->name[0] ? row->name : "Unnamed endpoint");
            snprintf(content[count++], 320, "Remote IP:");
            snprintf(content[count++], 320, "%s", ip_addr_str(&row->ip, address));
            snprintf(content[count++], 320, "First seen: %s", first);
            snprintf(content[count++], 320, "Last seen:  %s", last);
        } else {
            const struct tui_conversation *row = state->focus == 0 ? &snapshot->live[index] : &snapshot->top[index];

            snprintf(content[count++], 320, "Application: %s", row->key.application[0] ? row->key.application : "unresolved");
            timestamp(row->totals.first_seen, first);
            timestamp(row->totals.last_seen, last);
            snprintf(content[count++], 320, "%s", row->name[0] ? row->name : "Unnamed conversation");
            snprintf(content[count++], 320, "Remote IP:");
            snprintf(content[count++], 320, "%s", ip_addr_str(&row->key.remote_ip, address));
            snprintf(content[count++], 320, "Local IP:");
            snprintf(content[count++], 320, "%s", ip_addr_str(&row->key.us_ip, address));
            snprintf(content[count++], 320, "%s, remote port %u", row->key.protocol == 6 ? "TCP" : "UDP", row->key.remote_port);
            snprintf(content[count++], 320, "Download: %" PRIu64 " bytes, %" PRIu64 " packets", row->totals.bytes_in, row->totals.packets_in);
            snprintf(content[count++], 320, "Upload:   %" PRIu64 " bytes, %" PRIu64 " packets", row->totals.bytes_out, row->totals.packets_out);
            snprintf(content[count++], 320, "First seen: %s", first);
            snprintf(content[count++], 320, "Last seen:  %s", last);
            snprintf(content[count++], 320, "Name source: %s", row->name[0] ? "recorded DNS association" : "unknown");
        }
    } else {
        snprintf(content[count++], 320, "The selected entry is no longer in this view.");
    }

    const size_t visible = (size_t)(height - 3);
    const size_t maximum = count > visible ? count - visible : 0;
    const size_t scroll = state->modal_scroll < maximum ? state->modal_scroll : maximum;

    for (int row = 0; row < height - 3 && scroll + (size_t)row < count; row++) {
        text(p.y + 1 + row, p.x + 2, p.width - 4, row == 0 ? A_BOLD : 0,
             "%s", content[scroll + (size_t)row]);
    }

    text(p.y + p.height - 2, p.x + 2, p.width - 4, A_DIM,
         "Up/Down scroll | Enter/Esc close | q quit");
}

void tui_screen_draw(const struct tui_snapshot *snapshot, const struct tui_options *options,
                       const struct tui_screen *state, const char *path,
                       const char *error, int64_t now) {
    erase();

    if (COLS < 60 || LINES < 16) {
        text(0, 0, COLS, A_BOLD, "PIGEON: resize to at least 60x16; q quits");
        refresh();

        return;
    }

    char latest[32];

    if (snapshot->loaded_at == 0) {
        snprintf(latest, sizeof latest, "never");
    } else {
        age(now, snapshot->loaded_at, latest);
    }
    text(0, 1, COLS - 2, A_BOLD | COLOR_PAIR(1), "PIGEON | read-only viewer | %s | refresh %s ago",
         state->paused ? "AUTO-REFRESH PAUSED" : "1s refresh", latest);
    text(1, 1, COLS - 2, 0, "DB: %s | Search: %s | Proto: %s | IP: %s", path,
         options->search[0] ? options->search : "all", options->protocol == 6 ? "TCP" : options->protocol == 17 ? "UDP" : "any",
         options->family == 4 ? "v4" : options->family == 6 ? "v6" : "any");

    const struct panel summary = { 2, 0, 6, COLS };

    overview(summary, snapshot, now);

    if (COLS >= 110 && LINES >= 26) {
        const int bottom_height = LINES >= 34 ? 8 : 6;
        const int main_height = LINES - 10 - bottom_height;
        const int left_width = COLS / 2;
        const struct panel left = { 8, 0, main_height, left_width };
        const struct panel right = { 8, left_width, main_height, COLS - left_width };
        const struct panel bottom = { 8 + main_height, 0, bottom_height, COLS };

        conversation_panel(left, snapshot, options, state, 0, now);
        conversation_panel(right, snapshot, options, state, 1, now);
        endpoint_panel(bottom, snapshot, state);
    } else {
        const struct panel list = { 8, 0, LINES - 10, COLS };

        if (state->focus == 2) {
            endpoint_panel(list, snapshot, state);
        } else {
            conversation_panel(list, snapshot, options, state, state->focus, now);
        }
    }

    text(LINES - 2, 1, COLS - 2, error[0] ? COLOR_PAIR(3) : A_DIM,
         "%s", error[0] ? error : "Tab panel | arrows select | Enter details | / search | s sort | r recent | f/v filters | p pause");
    text(LINES - 1, 1, COLS - 2, A_DIM, "? help | q quit (collector keeps running) | Lists show up to 200 matches");

    if (state->details || state->help) {
        modal(snapshot, state);
    }

    if (state->searching) {
        text(LINES - 1, 0, COLS, A_REVERSE, "Search: %s  [Enter apply, Esc cancel]", state->draft);
    }

    refresh();
}

int tui_screen_key(int key, const struct tui_snapshot *snapshot,
                    struct tui_options *options, struct tui_screen *state) {
    if (state->searching) {
        const size_t length = strlen(state->draft);

        if (key == 27) {
            state->searching = 0;
        } else if (key == '\n' || key == KEY_ENTER) {
            memcpy(options->search, state->draft, sizeof options->search);
            state->searching = 0;

            return TUI_KEY_REFRESH;
        } else if ((key == KEY_BACKSPACE || key == 127 || key == 8) && length != 0) {
            state->draft[length - 1] = '\0';
        } else if (key == 21) {
            state->draft[0] = '\0';
        } else if (key >= 32 && key <= 126 && length + 1 < sizeof state->draft) {
            state->draft[length] = (char)key;
            state->draft[length + 1] = '\0';
        }

        return 0;
    }

    if (key == 'q' || key == 3) {
        return TUI_KEY_QUIT;
    }

    if (state->help || state->details) {
        const size_t lines = state->help ? 16 : state->focus == 2 ? 5 : 12;
        const int visible = (LINES < 23 ? LINES - 4 : 19) - 3;
        const size_t maximum = visible > 0 && lines > (size_t)visible ? lines - (size_t)visible : 0;

        if (key == 27 || key == '\n' || key == KEY_ENTER || key == '?') {
            state->help = state->details = 0;
        } else if (key == KEY_DOWN && state->modal_scroll < maximum) {
            state->modal_scroll++;
        } else if (key == KEY_UP && state->modal_scroll != 0) {
            state->modal_scroll--;
        }

        return 0;
    }

    const size_t count = panel_count(snapshot, state->focus);
    size_t *selected = &state->selected[state->focus];

    switch (key) {
        case '\t':
            state->focus = (state->focus + 1) % 3;
            break;

        case KEY_BTAB:
            state->focus = (state->focus + 2) % 3;
            break;

        case KEY_DOWN:
        case 'j':
            if (*selected + 1 < count) {
                (*selected)++;
            }

            break;

        case KEY_UP:
        case 'k':
            if (*selected != 0) {
                (*selected)--;
            }

            break;

        case KEY_NPAGE:
            *selected = count == 0 ? 0 : *selected + 10 < count ? *selected + 10 : count - 1;
            break;

        case KEY_PPAGE:
            *selected = *selected > 10 ? *selected - 10 : 0;
            break;

        case KEY_HOME:
            *selected = 0;
            break;

        case KEY_END:
            *selected = count == 0 ? 0 : count - 1;
            break;

        case '\n':
        case KEY_ENTER:
            state->details = count != 0;
            state->modal_scroll = 0;
            break;

        case '?':
            state->help = 1;
            state->modal_scroll = 0;
            break;

        case '/':
            memcpy(state->draft, options->search, sizeof state->draft);
            state->searching = 1;
            break;

        case 27:
            options->search[0] = '\0';

            return TUI_KEY_REFRESH;

        case 's':
            options->sort = (options->sort + 1) % 3;

            return TUI_KEY_REFRESH;

        case 'f':
            options->protocol = options->protocol == 0 ? 6 : options->protocol == 6 ? 17 : 0;

            return TUI_KEY_REFRESH;

        case 'v':
            options->family = options->family == 0 ? 4 : options->family == 4 ? 6 : 0;

            return TUI_KEY_REFRESH;

        case 'r':
            options->recent_seconds = options->recent_seconds == 30 ? 120
                                     : options->recent_seconds == 120 ? 0
                                     : options->recent_seconds == 0 ? 10 : 30;

            return TUI_KEY_REFRESH;

        case 'p':
            state->paused = !state->paused;

            return state->paused ? 0 : TUI_KEY_REFRESH;

        default:
            break;
    }

    return 0;
}

void tui_screen_reselect(const struct tui_snapshot *old, const struct tui_snapshot *next,
                          struct tui_screen *state) {
    for (int focus = 0; focus < 3; focus++) {
        const size_t count = panel_count(next, focus);
        const size_t previous = state->selected[focus];

        state->selected[focus] = count == 0 ? 0 : previous < count ? previous : count - 1;

        if (previous >= panel_count(old, focus)) {
            continue;
        }

        for (size_t i = 0; i < count; i++) {
            int same;

            if (focus == 2) {
                same = ip_addr_equal(&old->endpoints[previous].ip, &next->endpoints[i].ip);
            } else {
                const struct tui_conversation *a = focus == 0 ? old->live : old->top;
                const struct tui_conversation *b = focus == 0 ? next->live : next->top;

                same = flow_key_equal(&a[previous].key, &b[i].key);
            }

            if (same) {
                state->selected[focus] = i;
                break;
            }
        }
    }
}
