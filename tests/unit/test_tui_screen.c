#include <curses.h>
#include <stdlib.h>
#include <string.h>

#include "../t.h"
#include "tui/screen.h"

static int contains(const char *needle) {
    char line[256];

    for (int y = 0; y < LINES; y++) {
        const int width = COLS < 255 ? COLS : 255;

        for (int x = 0; x < width; x++) {
            line[x] = (char)(mvwinch(curscr, y, x) & A_CHARTEXT);
        }

        line[width] = '\0';

        if (strstr(line, needle) != NULL) {
            return 1;
        }
    }

    return 0;
}

int main(void) {
    FILE *output = tmpfile();
    FILE *input = tmpfile();

    CHECK(output != NULL && input != NULL);

    SCREEN *terminal = newterm("xterm", output, input);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };
    struct tui_screen state = { 0 };

    CHECK(terminal != NULL && snapshot != NULL);
    CHECK(resizeterm(40, 140) == OK);

    snapshot->live_count = snapshot->top_count = 1;
    CHECK(ip_addr_parse("2001:db8::10", &snapshot->live[0].key.us_ip) == 0);
    CHECK(ip_addr_parse("2001:db8::42", &snapshot->live[0].key.remote_ip) == 0);
    snapshot->live[0].key.protocol = 6;
    snapshot->live[0].key.remote_port = 443;
    snprintf(snapshot->live[0].name, sizeof snapshot->live[0].name, "v6.test");
    snapshot->top[0] = snapshot->live[0];
    snapshot->history_count = 2;
    snapshot->history[0] = (struct tui_sample) { .down = 1024, .up = 0, .seconds = 2 };
    snapshot->history[1] = (struct tui_sample) { .down = 0, .up = 512, .seconds = 3 };

    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("Live traffic"));
    CHECK(contains("Top Conversations"));
    CHECK(contains("New endpoints"));
    CHECK(contains("v6.test -> 2001:db8::42"));
    CHECK(contains("v6.test -> [2001:db8::42]:443/tcp"));
    CHECK(contains("5s | 0..1.0 KiB/s"));
    CHECK(contains("@_"));
    CHECK(contains("_="));

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
    tui_screen_key(KEY_DOWN, snapshot, &options, &state);
    tui_screen_key(27, snapshot, &options, &state);
    CHECK(state.details == 0);

    CHECK(resizeterm(10, 40) == OK);
    tui_screen_draw(snapshot, &options, &state, "test.db", "", 1000);
    CHECK(contains("60"));
    CHECK(tui_screen_key('q', snapshot, &options, &state) == TUI_KEY_QUIT);

    endwin();
    delscreen(terminal);
    free(snapshot);
    fclose(input);
    fclose(output);

    return 0;
}
