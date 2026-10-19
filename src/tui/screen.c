#include "tui/screen.h"
#include "proto/protocol.h"

#include <curses.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

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

/* Trusted glyphs use the wide-character API. Database strings still pass
 * through text()'s ASCII sanitization, so they cannot inject terminal controls. */
static void direction_icon_styled(int y, int x, int incoming, int attributes) {
    if (y < 0 || y >= LINES || x < 0 || x >= COLS) {
        return;
    }

    const wchar_t glyph = incoming ? L'\u2193' : L'\u2191';
    const short pair = has_colors() ? (incoming ? 1 : 2) : 0;
    const wchar_t value[] = { glyph, L'\0' };
    cchar_t icon;

    if (wcwidth(glyph) == 1 && setcchar(&icon, value, A_BOLD | attributes, pair, NULL) == OK) {
        mvadd_wch(y, x, &icon);

        return;
    }

    attron(A_BOLD | attributes | COLOR_PAIR(pair));
    mvaddch(y, x, incoming ? 'v' : '^');
    attroff(A_BOLD | attributes | COLOR_PAIR(pair));
}

static void direction_icon(int y, int x, int incoming) {
    direction_icon_styled(y, x, incoming, 0);
}

static void traffic_heading(int y, int x, const char *label, int incoming) {
    text(y, x, 10, A_DIM, "%10s", label);
    direction_icon(y, x + 8 - (int)strlen(label), incoming);
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
         : focus == 2 ? snapshot->application_count : snapshot->endpoint_count;
}

static void abbreviate(const char *value, size_t width, size_t suffix, char out[384]) {
    const size_t length = strlen(value);

    if (length <= width) {
        snprintf(out, 384, "%s", value);

        return;
    }

    if (width <= 3) {
        memset(out, '.', width);
        out[width] = '\0';

        return;
    }

    size_t right = (width - 2) / 2;

    if (right < suffix) {
        right = suffix;
    }

    if (right > width - 4) {
        right = width - 4;
    }

    const size_t left = width - 3 - right;

    memcpy(out, value, left);
    memcpy(out + left, "...", 3);
    memcpy(out + left + 3, value + length - right, right);
    out[width] = '\0';
}

/* Spend the available columns on the address first. If even the address
 * cannot fit, make its abbreviation explicit; details retain the full value. */
static void endpoint_label(const char *name, const char *endpoint, int width, char out[384]) {
    if (width <= 0) {
        out[0] = '\0';

        return;
    }

    const size_t available = width < 384 ? (size_t)width : 383;
    const size_t endpoint_length = strlen(endpoint);
    const size_t name_length = strlen(name);
    const size_t minimum_name = name_length < 7 ? name_length : 7;

    if (name[0] == '\0' || available < endpoint_length + 4 + minimum_name) {
        const char *port = strrchr(endpoint, ':');
        const size_t suffix = port != NULL && strchr(port, '/') != NULL
                              ? strlen(port) + (port > endpoint && port[-1] == ']') : 0;

        abbreviate(endpoint, available, suffix, out);

        return;
    }

    char shortened[384];

    abbreviate(name, available - endpoint_length - 4, 0, shortened);

    const size_t shortened_length = strlen(shortened);

    memcpy(out, shortened, shortened_length);
    memcpy(out + shortened_length, " -> ", 4);
    memcpy(out + shortened_length + 4, endpoint, endpoint_length + 1);
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
         "Totals:   Down %s    Up %s   Conversations %" PRIu64 "   Remote IPs %" PRIu64,
         down, up, snapshot->conversations, snapshot->remote_ips);
    direction_icon(p.y + 1, p.x + 10, 1);
    direction_icon(p.y + 1, p.x + 19 + (int)strlen(down), 0);

    if (snapshot->rates_valid) {
        bytes(snapshot->rate_down, down);
        bytes(snapshot->rate_up, up);
        text(p.y + 2, p.x + 2, p.width - 4, 0,
             "DB delta rate:   Down %s/s    Up %s/s   Latest packet: %s ago", down, up,
             snapshot->has_packets ? latest : "none");
        direction_icon(p.y + 2, p.x + 17, 1);
        direction_icon(p.y + 2, p.x + 28 + (int)strlen(down), 0);
    } else {
        text(p.y + 2, p.x + 2, p.width - 4, A_DIM,
             "DB delta rate: waiting for next sample   Latest packet: %s",
             snapshot->has_packets ? latest : "none");
    }

    const size_t capacity = (size_t)(p.width - 40) < TUI_HISTORY ? (size_t)(p.width - 40) : TUI_HISTORY;
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
             "  %s [%s] %.0fs | 0..%s/s", direction == 0 ? "Down" : "Up  ", graph, seconds, scale);
        direction_icon(p.y + 3 + direction, p.x + 2, direction == 0);
    }
}

static void conversation_panel(struct panel p, const struct tui_snapshot *snapshot,
                                 const struct tui_options *options, const struct tui_screen *state,
                                 int focus, int64_t now) {
    const int live = focus == 0;
    const char *sorts[] = { "total", "download", "upload" };
    char title[100];

    if (live) {
        const char *live_sorts[] = { "recency", "total/s", "down/s", "up/s" };

        if (options->recent_seconds == 0) {
            snprintf(title, sizeof title, "Live traffic | all recorded | %s", live_sorts[options->live_sort]);
        } else {
            snprintf(title, sizeof title, "Live traffic | last %ds | %s", options->recent_seconds,
                     live_sorts[options->live_sort]);
        }
    } else {
        snprintf(title, sizeof title, "Top Conversations | all recorded | %s", sorts[options->sort]);
    }

    draw_border(p, title, state->focus == focus);

    const int show_seen = live && p.width >= 80;
    const int application_width = p.width >= (live ? 110 : 80) ? 18 : 12;
    const int endpoint_width = p.width - 30 - application_width - (show_seen ? 7 : 0);
    const struct tui_conversation *rows = live ? snapshot->live : snapshot->top;
    const size_t count = live ? snapshot->live_count : snapshot->top_count;
    const int visible = p.height - 4;
    const size_t selected = state->selected[focus];
    const size_t start = selected >= (size_t)visible ? selected - (size_t)visible + 1 : 0;

    text(p.y + 1, p.x + 1, p.width - 2, A_DIM, "  IO %-*s %-*s",
         application_width, "Application", endpoint_width, "Endpoint");

    const int down_x = p.x + 8 + application_width + endpoint_width;

    traffic_heading(p.y + 1, down_x, live ? "Down/s" : "Down", 1);
    traffic_heading(p.y + 1, down_x + 11, live ? "Up/s" : "Up", 0);

    if (show_seen) {
        text(p.y + 1, down_x + 22, 6, A_DIM, "%6s", "Seen");
    }

    for (int i = 0; i < visible && start + (size_t)i < count; i++) {
        const size_t index = start + (size_t)i;
        const struct tui_conversation *row = &rows[index];
        char address[IP_ADDR_STR_LEN];
        char endpoint[IP_ADDR_STR_LEN + 16];
        char label[384];
        char last[32];
        char down[20];
        char up[20];

        ip_addr_str(&row->key.remote_ip, address);

        if (protocol_has_ports(row->key.protocol)) {
            snprintf(endpoint, sizeof endpoint, "%s%s%s:%u/%s", row->key.remote_ip.family == 6 ? "[" : "",
                     address, row->key.remote_ip.family == 6 ? "]" : "",
                     row->key.remote_port, row->quic ? "QUIC(UDP)" : protocol_label(row->key.protocol));
        } else {
            snprintf(endpoint, sizeof endpoint, "%s/%s", address, protocol_label(row->key.protocol));
        }
        endpoint_label(row->name, endpoint, endpoint_width, label);
        age(now, row->totals.last_seen, last);

        if (live && !row->rates_valid) {
            snprintf(down, sizeof down, "--");
            snprintf(up, sizeof up, "--");
        } else {
            bytes(live ? row->rate_down : (double)row->totals.bytes_in, down);
            bytes(live ? row->rate_up : (double)row->totals.bytes_out, up);
        }

        const int attributes = state->focus == focus && selected == index ? A_REVERSE : 0;

        if (show_seen) {
            text(p.y + 2 + i, p.x + 1, p.width - 2, attributes,
                 "%c    %-*.*s %-*.*s %10.10s %10.10s %6.6s", selected == index ? '>' : ' ',
                 application_width, application_width, row->key.application[0] ? row->key.application : "unresolved",
                 endpoint_width, endpoint_width, label, down, up, last);
        } else {
            text(p.y + 2 + i, p.x + 1, p.width - 2, attributes,
                 "%c    %-*.*s %-*.*s %10.10s %10.10s", selected == index ? '>' : ' ',
                 application_width, application_width, row->key.application[0] ? row->key.application : "unresolved",
                 endpoint_width, endpoint_width, label, down, up);
        }

        if (row->totals.packets_in != 0) {
            direction_icon_styled(p.y + 2 + i, p.x + 3, 1, attributes);
        }

        if (row->totals.packets_out != 0) {
            direction_icon_styled(p.y + 2 + i, p.x + 4, 0, attributes);
        }
    }

    if (count == 0) {
        text(p.y + 2, p.x + 2, p.width - 4, A_DIM, "No matching conversations");
    }

    text(p.y + p.height - 2, p.x + 2, p.width - 4, A_DIM,
         live ? "%zu newest matches (max %d) | -- waiting | Enter: details"
              : "%zu shown (limit %d) | Enter: details", count, TUI_MAX_ROWS);
}

static void application_panel(struct panel p, const struct tui_snapshot *snapshot,
                                const struct tui_options *options, const struct tui_screen *state) {
    const char *sorts[] = { "total", "download", "upload" };
    char title[100];

    snprintf(title, sizeof title, "Applications | all recorded | %s", sorts[options->sort]);
    draw_border(p, title, state->focus == 2);

    const int name_width = p.width - 26;
    const int visible = p.height - 4;
    const size_t selected = state->selected[2];
    const size_t start = selected >= (size_t)visible ? selected - (size_t)visible + 1 : 0;

    text(p.y + 1, p.x + 1, p.width - 2, A_DIM, "  %-*s", name_width, "Application");
    traffic_heading(p.y + 1, p.x + 4 + name_width, "Down", 1);
    traffic_heading(p.y + 1, p.x + 15 + name_width, "Up", 0);

    for (int i = 0; i < visible && start + (size_t)i < snapshot->application_count; i++) {
        const size_t index = start + (size_t)i;
        const struct tui_application *row = &snapshot->applications[index];
        char down[20];
        char up[20];

        bytes(row->bytes_down, down);
        bytes(row->bytes_up, up);

        const int active = options->application_selected && strcmp(options->application, row->name) == 0;

        text(p.y + 2 + i, p.x + 1, p.width - 2,
             state->focus == 2 && selected == index ? A_REVERSE : 0,
             "%c %-*.*s %10.10s %10.10s", active ? '*' : selected == index ? '>' : ' ',
             name_width, name_width, row->name[0] ? row->name : "unresolved", down, up);
    }

    if (snapshot->application_count == 0) {
        text(p.y + 2, p.x + 2, p.width - 4, A_DIM, "No recorded applications");
    }

    text(p.y + p.height - 2, p.x + 2, p.width - 4, A_DIM,
         "%zu shown | Enter filter | d details | a all apps", snapshot->application_count);
}

static void endpoint_panel(struct panel p, const struct tui_snapshot *snapshot,
                            const struct tui_screen *state) {
    draw_border(p, "New endpoints | first seen in this database", state->focus == 3);

    const int visible = p.height - 3;
    const size_t selected = state->selected[3];
    const size_t start = selected >= (size_t)visible ? selected - (size_t)visible + 1 : 0;

    for (int i = 0; i < visible && start + (size_t)i < snapshot->endpoint_count; i++) {
        const size_t index = start + (size_t)i;
        const struct tui_endpoint *row = &snapshot->endpoints[index];
        char address[IP_ADDR_STR_LEN];
        char label[384];
        char first[40];

        ip_addr_str(&row->ip, address);
        endpoint_label(row->name, address, p.width - 25, label);
        timestamp(row->first_seen, first);
        text(p.y + 1 + i, p.x + 1, p.width - 2,
             state->focus == 3 && selected == index ? A_REVERSE : 0,
             "%c %.19s  %s", selected == index ? '>' : ' ', first, label);
    }

    if (snapshot->endpoint_count == 0) {
        text(p.y + 1, p.x + 2, p.width - 4, A_DIM, "No matching endpoints");
    }

    text(p.y + p.height - 2, p.x + 2, p.width - 4, A_DIM,
         "%zu remote IPs shown (limit %d); protocol filter does not apply", snapshot->endpoint_count, TUI_MAX_ROWS);
}

static int modal_text_width(void) {
    const int width = (COLS < 104 ? COLS - 4 : 100) - 4;

    return width > 0 ? width : 1;
}

static size_t name_line_count(const char *name) {
    const size_t width = (size_t)modal_text_width();
    const size_t length = strlen(name);

    return length == 0 ? 1 : (length + width - 1) / width;
}

static void modal_name(char content[24][320], size_t *count, const char *name) {
    const size_t width = (size_t)modal_text_width();
    const size_t length = strlen(name);

    for (size_t offset = 0; offset < length && *count < 24; offset += width) {
        snprintf(content[(*count)++], 320, "%.*s", (int)width, name + offset);
    }
}

static void modal(const struct tui_snapshot *snapshot, const struct tui_screen *state) {
    const int width = COLS < 104 ? COLS - 4 : 100;
    const int height = LINES < 23 ? LINES - 4 : 19;
    struct panel p = { (LINES - height) / 2, (COLS - width) / 2, height, width };

    for (int y = p.y; y < p.y + p.height; y++) {
        mvhline(y, p.x, ' ', p.width);
    }

    draw_border(p, state->help ? "Help" : state->focus == 2 ? "Selected application" : "Selected endpoint", 1);

    char content[24][320] = { { 0 } };
    size_t count = 0;

    if (state->help) {
        const char *lines[] = {
            "Tab / Shift-Tab  Change focused panel", "Up/Down, j/k     Select row; PgUp/PgDn, Home/End also work",
            "Enter           Details; on Applications: filter conversations", "/               Search name, remote IP, or application (conversations)",
            "s: cumulative sort | l: live recency/total/down/up", "r               Live window: 10s / 30s / 120s / all",
            "f               Protocol: any / TCP / UDP / ICMP / ICMPv6 / ESP", "v               Address family: any / IPv4 / IPv6",
            "p               Pause auto-refresh; collector keeps running", "q / Ctrl-C      Quit viewer; collector keeps running",
            "Rates are database counter deltas, not NIC speed.", "IO: down=incoming, up=outgoing; observed packet directions.",
            "Graphs: old -> new, shared scale; _ is zero, @ is peak.", "No collector heartbeat is stored. Idle is not stopped.",
            "d: details | a: all apps | Esc: clear app filter and search", "Names are recorded DNS associations, not service proof."
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
            const struct tui_application *row = &snapshot->applications[index];

            timestamp(row->last_seen, last);
            snprintf(content[count++], 320, "Application: %s", row->name[0] ? row->name : "unresolved");
            snprintf(content[count++], 320, "Download: %.0f bytes", row->bytes_down);
            snprintf(content[count++], 320, "Upload:   %.0f bytes", row->bytes_up);
            snprintf(content[count++], 320, "Conversations: %" PRIu64, row->conversations);
            snprintf(content[count++], 320, "Remote IPs: %" PRIu64, row->remote_ips);
            snprintf(content[count++], 320, "Last seen: %s", last);
            snprintf(content[count++], 320, "Enter on this panel filters conversation lists.");
        } else if (state->focus == 3) {
            const struct tui_endpoint *row = &snapshot->endpoints[index];

            timestamp(row->first_seen, first);
            timestamp(row->last_seen, last);
            modal_name(content, &count, row->name[0] ? row->name : "Unnamed endpoint");
            snprintf(content[count++], 320, "Remote IP:");
            snprintf(content[count++], 320, "%s", ip_addr_str(&row->ip, address));
            snprintf(content[count++], 320, "First seen: %s", first);
            snprintf(content[count++], 320, "Last seen:  %s", last);
        } else {
            const struct tui_conversation *row = state->focus == 0 ? &snapshot->live[index] : &snapshot->top[index];

            snprintf(content[count++], 320, "Application: %s", row->key.application[0] ? row->key.application : "unresolved");
            timestamp(row->totals.first_seen, first);
            timestamp(row->totals.last_seen, last);
            modal_name(content, &count, row->name[0] ? row->name : "Unnamed conversation");
            snprintf(content[count++], 320, "Remote IP:");
            snprintf(content[count++], 320, "%s", ip_addr_str(&row->key.remote_ip, address));
            snprintf(content[count++], 320, "Local IP:");
            snprintf(content[count++], 320, "%s", ip_addr_str(&row->key.us_ip, address));
            if (protocol_has_ports(row->key.protocol)) {
                snprintf(content[count++], 320, "%s, remote port %u", row->quic ? "QUIC (UDP)" : protocol_name(row->key.protocol), row->key.remote_port);
            } else {
                snprintf(content[count++], 320, "%s, no ports", protocol_name(row->key.protocol));
            }
            snprintf(content[count++], 320, "Download: %" PRIu64 " bytes, %" PRIu64 " packets", row->totals.bytes_in, row->totals.packets_in);
            snprintf(content[count++], 320, "Upload:   %" PRIu64 " bytes, %" PRIu64 " packets", row->totals.bytes_out, row->totals.packets_out);
            snprintf(content[count++], 320, "First seen: %s", first);
            snprintf(content[count++], 320, "Last seen:  %s", last);
            snprintf(content[count++], 320, "Name source: %s", row->name[0] ? "recorded DNS association" : "unknown");

            if (state->focus == 0) {
                char down[20];
                char up[20];

                bytes(row->rate_down, down);
                bytes(row->rate_up, up);
                snprintf(content[count++], 320, "Download rate: %s%s", row->rates_valid ? down : "waiting for next sample",
                         row->rates_valid ? "/s (DB estimate)" : "");
                snprintf(content[count++], 320, "Upload rate:   %s%s", row->rates_valid ? up : "waiting for next sample",
                         row->rates_valid ? "/s (DB estimate)" : "");
            }
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
    text(1, 1, COLS - 2, 0, "App: %s | Search: %s | Proto: %s | IP: %s | DB: %s",
         options->application_selected ? (options->application[0] ? options->application : "unresolved") : "all",
         options->search[0] ? options->search : "all", options->protocol == 0 ? "any" : protocol_name(options->protocol),
         options->family == 4 ? "v4" : options->family == 6 ? "v6" : "any", path);

    const struct panel summary = { 2, 0, 6, COLS };

    overview(summary, snapshot, now);

    if (COLS >= 110 && LINES >= 26) {
        const int bottom_height = LINES >= 34 ? 10 : 7;
        const int main_height = LINES - 10 - bottom_height;
        const int left_width = COLS / 2;
        const struct panel left = { 8, 0, main_height, left_width };
        const struct panel right = { 8, left_width, main_height, COLS - left_width };
        const struct panel apps = { 8 + main_height, 0, bottom_height, left_width };
        const struct panel endpoints = { 8 + main_height, left_width, bottom_height, COLS - left_width };

        conversation_panel(left, snapshot, options, state, 0, now);
        conversation_panel(right, snapshot, options, state, 1, now);
        application_panel(apps, snapshot, options, state);
        endpoint_panel(endpoints, snapshot, state);
    } else {
        const struct panel list = { 8, 0, LINES - 10, COLS };

        if (state->focus == 2) {
            application_panel(list, snapshot, options, state);
        } else if (state->focus == 3) {
            endpoint_panel(list, snapshot, state);
        } else {
            conversation_panel(list, snapshot, options, state, state->focus, now);
        }
    }

    text(LINES - 2, 1, COLS - 2, error[0] ? COLOR_PAIR(3) : A_DIM,
         "%s", error[0] ? error : state->focus == 2
         ? "Tab panel | arrows select | Enter filter app | / search | s sort | p pause"
         : "Tab panel | arrows select | Enter details | / search | s sort | r recent | f/v filters | p pause");
    text(LINES - 1, 1, COLS - 2, A_DIM, "l live sort | a all apps | d details | ? help | q quit | Lists show up to 200 matches");

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
        size_t lines = state->help ? 16 : state->focus == 3 ? 5 : state->focus == 2 ? 7 : state->focus == 0 ? 14 : 12;

        if (!state->help && state->focus != 2 && panel_count(snapshot, state->focus) != 0) {
            const size_t index = state->selected[state->focus];
            const char *name = state->focus == 3 ? snapshot->endpoints[index].name
                             : state->focus == 0 ? snapshot->live[index].name : snapshot->top[index].name;

            lines += name_line_count(name) - 1;
        }

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
            state->focus = (state->focus + 1) % 4;
            break;

        case KEY_BTAB:
            state->focus = (state->focus + 3) % 4;
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
            if (state->focus == 2 && count != 0) {
                memcpy(options->application, snapshot->applications[*selected].name, sizeof options->application);
                options->application_selected = 1;
                options->search[0] = '\0';
                state->focus = 1;
                state->selected[0] = state->selected[1] = 0;

                return TUI_KEY_REFRESH;
            }

            state->details = count != 0;
            state->modal_scroll = 0;
            break;

        case 'd':
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

        case 'a':
            options->application_selected = 0;
            options->application[0] = '\0';

            return TUI_KEY_REFRESH;

        case 27:
            options->application_selected = 0;
            options->application[0] = '\0';
            options->search[0] = '\0';

            return TUI_KEY_REFRESH;

        case 's':
            options->sort = (options->sort + 1) % 3;

            return TUI_KEY_REFRESH;

        case 'l':
            options->live_sort = (options->live_sort + 1) % 4;

            return TUI_KEY_REFRESH;

        case 'f':
            options->protocol = options->protocol == 0 ? 6 : options->protocol == 6 ? 17 :
                                options->protocol == 17 ? 1 : options->protocol == 1 ? 58 :
                                options->protocol == 58 ? 50 : 0;

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
    for (int focus = 0; focus < 4; focus++) {
        const size_t count = panel_count(next, focus);
        const size_t previous = state->selected[focus];

        state->selected[focus] = count == 0 ? 0 : previous < count ? previous : count - 1;

        if (previous >= panel_count(old, focus)) {
            continue;
        }

        for (size_t i = 0; i < count; i++) {
            int same;

            if (focus == 2) {
                same = strcmp(old->applications[previous].name, next->applications[i].name) == 0;
            } else if (focus == 3) {
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
