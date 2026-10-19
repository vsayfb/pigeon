#include <curses.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

#include "../t.h"
#include "tui/screen.h"

static int columns_contain(int start, int columns, const char *needle) {
    char line[256];

    for (int y = 0; y < LINES; y++) {
        const int width = columns < 255 ? columns : 255;

        for (int x = 0; x < width; x++) {
            line[x] = (char)(mvwinch(curscr, y, start + x) & A_CHARTEXT);
        }

        line[width] = '\0';

        if (strstr(line, needle) != NULL) {
            return 1;
        }
    }

    return 0;
}

static int contains(const char *needle) {
    return columns_contain(0, COLS, needle);
}

static void test_endpoint_abbreviations(void) {
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };
    struct tui_screen state = { 0 };
    const char *long_name = "rr1--sn-a5mekn7s.something-long.googlevideo.example.test";

    CHECK(snapshot != NULL);
    CHECK(resizeterm(40, 180) == OK);
    snapshot->live_count = snapshot->top_count = snapshot->endpoint_count = 1;
    CHECK(ip_addr_parse("192.0.2.10", &snapshot->live[0].key.us_ip) == 0);
    CHECK(ip_addr_parse("173.194.10.38", &snapshot->live[0].key.remote_ip) == 0);
    snapshot->live[0].key.remote_port = 65535;
    snapshot->live[0].key.protocol = 6;
    strcpy(snapshot->live[0].name, long_name);
    snapshot->top[0] = snapshot->live[0];
    snapshot->endpoints[0].ip = snapshot->live[0].key.remote_ip;
    strcpy(snapshot->endpoints[0].name, long_name);

    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(columns_contain(0, 90, " -> 173.194.10.38:65535/tcp"));
    CHECK(columns_contain(90, 90, " -> 173.194.10.38:65535/tcp"));
    CHECK(columns_contain(0, 90, "..."));
    CHECK(columns_contain(90, 90, "..."));
    CHECK(contains(" -> 173.194.10.38"));
    CHECK(!contains(long_name));

    tui_screen_key('d', snapshot, &options, &state);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains(long_name));
    tui_screen_key(27, snapshot, &options, &state);

    CHECK(ip_addr_parse("2001:db8::10", &snapshot->live[0].key.us_ip) == 0);
    CHECK(ip_addr_parse("2001:db8::42", &snapshot->live[0].key.remote_ip) == 0);
    snapshot->top[0] = snapshot->live[0];
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(columns_contain(0, 90, " -> [2001:db8::42]:65535/tcp"));
    CHECK(columns_contain(90, 90, " -> [2001:db8::42]:65535/tcp"));

    snapshot->live[0].name[0] = '\0';
    snapshot->top[0] = snapshot->live[0];
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(columns_contain(0, 90, "[2001:db8::42]:65535/tcp"));
    CHECK(!columns_contain(0, 90, " -> "));

    CHECK(ip_addr_parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &snapshot->live[0].key.remote_ip) == 0);
    strcpy(snapshot->live[0].name, long_name);
    CHECK(resizeterm(16, 60) == OK);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("..."));
    CHECK(contains(":65535/tcp"));

    tui_screen_key('d', snapshot, &options, &state);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);

    char first_line[53];

    memcpy(first_line, long_name, 52);
    first_line[52] = '\0';
    CHECK(contains(first_line));
    CHECK(contains(long_name + 52));
    tui_screen_key(27, snapshot, &options, &state);

    CHECK(resizeterm(40, 180) == OK);
    free(snapshot);
}

static void check_direction_icon(int y, int x, wchar_t expected, short expected_pair) {
    cchar_t cell;
    wchar_t value[CCHARW_MAX];
    attr_t attributes;
    short pair;

    CHECK(mvwin_wch(curscr, y, x, &cell) == OK);
    CHECK(getcchar(&cell, value, &attributes, &pair, NULL) == OK);
    CHECK(value[0] == expected);
    CHECK((attributes & A_BOLD) != 0);
    CHECK(pair == expected_pair);
}

static void test_ascii_icons(void) {
    CHECK(setlocale(LC_ALL, "C") != NULL);

    FILE *output = tmpfile();
    FILE *input = tmpfile();

    CHECK(output != NULL && input != NULL);

    SCREEN *terminal = newterm("xterm", output, input);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };
    struct tui_screen state = { 0 };

    CHECK(terminal != NULL && snapshot != NULL);
    CHECK(resizeterm(16, 60) == OK);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK((mvwinch(curscr, 3, 10) & A_CHARTEXT) == 'v');
    CHECK((mvwinch(curscr, 3, 22) & A_CHARTEXT) == '^');
    CHECK(contains("Down/s"));
    CHECK(contains("Up/s"));

    endwin();
    delscreen(terminal);
    free(snapshot);
    fclose(input);
    fclose(output);
}

int main(void) {
    CHECK(setlocale(LC_ALL, "C.UTF-8") != NULL);

    FILE *output = tmpfile();
    FILE *input = tmpfile();

    CHECK(output != NULL && input != NULL);

    SCREEN *terminal = newterm("xterm", output, input);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };
    struct tui_screen state = { 0 };

    CHECK(terminal != NULL && snapshot != NULL);
    CHECK(start_color() == OK);
    CHECK(use_default_colors() == OK);
    CHECK(init_pair(1, COLOR_CYAN, -1) == OK);
    CHECK(init_pair(2, COLOR_GREEN, -1) == OK);
    CHECK(init_pair(3, COLOR_YELLOW, -1) == OK);
    CHECK(resizeterm(40, 180) == OK);

    snapshot->live_count = snapshot->top_count = 1;
    CHECK(ip_addr_parse("2001:db8::10", &snapshot->live[0].key.us_ip) == 0);
    CHECK(ip_addr_parse("2001:db8::42", &snapshot->live[0].key.remote_ip) == 0);
    snapshot->live[0].key.protocol = 6;
    snapshot->live[0].key.remote_port = 443;
    strcpy(snapshot->live[0].key.application, "firefox");
    snprintf(snapshot->live[0].name, sizeof snapshot->live[0].name, "v6.test");
    snapshot->top[0] = snapshot->live[0];
    snapshot->application_count = 3;
    strcpy(snapshot->applications[0].name, "firefox");
    strcpy(snapshot->applications[1].name, "chromium");
    snapshot->applications[0].bytes_down = 1024;
    snapshot->history_count = 2;
    snapshot->history[0] = (struct tui_sample) { .down = 1024, .up = 0, .seconds = 2 };
    snapshot->history[1] = (struct tui_sample) { .down = 0, .up = 512, .seconds = 3 };

    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    check_direction_icon(3, 10, L'\u2193', 1);
    check_direction_icon(3, 22, L'\u2191', 2);
    check_direction_icon(5, 2, L'\u2193', 1);
    check_direction_icon(6, 2, L'\u2191', 2);
    check_direction_icon(9, 63, L'\u2193', 1);
    check_direction_icon(9, 76, L'\u2191', 2);
    CHECK(contains("Live traffic"));
    CHECK(contains("Top Conversations"));
    CHECK(contains("New endpoints"));
    CHECK(contains("Applications | all recorded"));
    CHECK(contains("firefox"));
    CHECK(contains("Down/s"));
    CHECK(contains("Up/s"));
    CHECK(contains("--"));
    CHECK(contains("v6.test -> [2001:db8::42]:443/tcp"));
    CHECK(contains("5s | 0..1.0 KiB/s"));
    CHECK(contains("@_"));
    CHECK(contains("_="));

    CHECK(resizeterm(26, 110) == OK);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("Applications | all recorded"));
    CHECK(contains("New endpoints"));

    CHECK(resizeterm(24, 80) == OK);

    for (int focus = 0; focus < 4; focus++) {
        const char *titles[] = { "Live traffic", "Top Conversations", "Applications", "New endpoints" };

        state.focus = focus;
        tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
        CHECK(contains(titles[focus]));
    }

    state.focus = 0;

    const char *live_titles[] = { "total/s", "down/s", "up/s", "recency" };

    for (int i = 0; i < 4; i++) {
        CHECK(tui_screen_key('l', snapshot, &options, &state) == TUI_KEY_REFRESH);
        tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
        CHECK(contains(live_titles[i]));
        CHECK(options.sort == TUI_SORT_TOTAL);
    }

    CHECK(options.live_sort == TUI_LIVE_RECENCY);
    CHECK(tui_screen_key('\t', snapshot, &options, &state) == 0);
    CHECK(state.focus == 1);
    CHECK(tui_screen_key('s', snapshot, &options, &state) == TUI_KEY_REFRESH);
    CHECK(options.sort == TUI_SORT_DOWNLOAD);
    CHECK(tui_screen_key('/', snapshot, &options, &state) == 0);
    CHECK(tui_screen_key('q', snapshot, &options, &state) == 0);
    CHECK(tui_screen_key('\n', snapshot, &options, &state) == TUI_KEY_REFRESH);
    CHECK(strcmp(options.search, "q") == 0);

    CHECK(resizeterm(16, 60) == OK);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("5s | 0..1.0 KiB/s"));

    tui_screen_key('\n', snapshot, &options, &state);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("2001:db8::42"));
    CHECK(contains("Application: firefox"));
    tui_screen_key(KEY_DOWN, snapshot, &options, &state);
    tui_screen_key(27, snapshot, &options, &state);
    CHECK(state.details == 0);

    state.focus = 0;
    snapshot->live[0].rates_valid = 1;
    snapshot->live[0].rate_down = 2048;
    snapshot->live[0].rate_up = 512;
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("Down/s"));
    CHECK(contains("2.0 KiB"));
    CHECK(contains("512 B"));
    tui_screen_key('d', snapshot, &options, &state);

    for (int i = 0; i < 5; i++) {
        tui_screen_key(KEY_DOWN, snapshot, &options, &state);
    }

    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("Download rate: 2.0 KiB/s"));
    CHECK(contains("Upload rate:   512 B/s"));
    tui_screen_key(27, snapshot, &options, &state);
    state.focus = 1;

    CHECK(tui_screen_key('\t', snapshot, &options, &state) == 0);
    CHECK(state.focus == 2);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("Applications | all recorded"));
    CHECK(tui_screen_key('d', snapshot, &options, &state) == 0);
    CHECK(state.details == 1);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("Application: firefox"));
    tui_screen_key(27, snapshot, &options, &state);
    CHECK(tui_screen_key('\n', snapshot, &options, &state) == TUI_KEY_REFRESH);
    CHECK(options.application_selected == 1 && strcmp(options.application, "firefox") == 0);
    CHECK(state.focus == 1 && options.search[0] == '\0');
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("App: firefox"));

    state.focus = 2;
    tui_screen_key(KEY_END, snapshot, &options, &state);
    CHECK(state.selected[2] == 2);
    CHECK(tui_screen_key('\n', snapshot, &options, &state) == TUI_KEY_REFRESH);
    CHECK(options.application_selected == 1 && options.application[0] == '\0');
    CHECK(tui_screen_key('a', snapshot, &options, &state) == TUI_KEY_REFRESH);
    CHECK(options.application_selected == 0);

    options.application_selected = 1;
    strcpy(options.application, "firefox");
    strcpy(options.search, "example");
    tui_screen_key(27, snapshot, &options, &state);
    CHECK(options.application_selected == 0 && options.search[0] == '\0');

    struct tui_snapshot *next = malloc(sizeof *next);

    CHECK(next != NULL);
    snapshot->live_count = 2;
    snapshot->live[1] = snapshot->live[0];
    strcpy(snapshot->live[1].key.application, "chromium");
    *next = *snapshot;
    next->live[0] = snapshot->live[1];
    next->live[1] = snapshot->live[0];
    state.selected[0] = 0;
    next->applications[0] = snapshot->applications[1];
    next->applications[1] = snapshot->applications[0];
    state.focus = 2;
    state.selected[2] = 0;
    tui_screen_reselect(snapshot, next, &state);
    CHECK(state.selected[2] == 1);
    CHECK(state.selected[0] == 1);

    next->application_count = 0;
    tui_screen_reselect(snapshot, next, &state);
    CHECK(state.selected[2] == 0);
    CHECK(tui_screen_key('\n', next, &options, &state) == 0);
    CHECK(options.application_selected == 0);
    free(next);

    state.focus = 3;
    tui_screen_key('\t', snapshot, &options, &state);
    CHECK(state.focus == 0);
    tui_screen_key(KEY_BTAB, snapshot, &options, &state);
    CHECK(state.focus == 3);

    test_endpoint_abbreviations();

    CHECK(resizeterm(10, 40) == OK);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("60"));
    CHECK(tui_screen_key('q', snapshot, &options, &state) == TUI_KEY_QUIT);

    endwin();
    delscreen(terminal);
    free(snapshot);
    fclose(input);
    fclose(output);
    test_ascii_icons();

    return 0;
}
