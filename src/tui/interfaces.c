#include "tui/interfaces.h"
#include "control/control.h"

#include <curses.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct interface_row {
    char name[64];
    char label[160];
    int enabled;
};

static int load_interfaces(const char *database, struct interface_row rows[128], char status[256]) {
    char reply[CONTROL_REPLY_LEN];

    if (control_request(database, "LIST", reply, sizeof reply) == -1) {
        snprintf(status, 256, "Collector unavailable: %.180s", strerror(errno));

        return 0;
    }

    if (strncmp(reply, "OK\t", 3) != 0) {
        snprintf(status, 256, "%.240s", reply);

        return 0;
    }

    char *state;
    char *line = strtok_r(reply, "\n", &state);
    char current[64];
    char mode[16];

    if (line == NULL || sscanf(line, "OK\t%63s\t%15s", current, mode) != 2) {
        snprintf(status, 256, "Invalid collector response");

        return 0;
    }

    snprintf(status, 256, "Capturing on %s (%s)", current, mode);
    rows[0] = (struct interface_row){ .name = "", .label = "Automatic (choose active supported interface)", .enabled = 1 };
    int count = 1;

    while (count < 128 && (line = strtok_r(NULL, "\n", &state)) != NULL) {
        char active[16];
        char supported[20];
        struct interface_row *row = &rows[count];

        if (sscanf(line, "%63s\t%15s\t%19s", row->name, active, supported) != 3) {
            continue;
        }

        row->enabled = strcmp(active, "active") == 0 && strcmp(supported, "supported") == 0;
        snprintf(row->label, sizeof row->label, "%s%s | %s | %s", row->name,
                 strcmp(row->name, current) == 0 ? " [current]" : "", active, supported);
        count++;
    }

    return count;
}

void tui_interfaces(const char *database, const volatile sig_atomic_t *stopping) {
    struct interface_row rows[128];
    char status[256] = "Discovering capture interfaces...";
    int count = 0;
    int selected = 0;
    int reload = 1;

    wtimeout(stdscr, 100);

    while (!*stopping) {
        erase();
        mvaddnstr(0, 1, "Capture interfaces | collector control", COLS > 2 ? COLS - 2 : 0);
        mvaddnstr(2, 1, status, COLS > 2 ? COLS - 2 : 0);

        const int visible = LINES > 7 ? LINES - 7 : 0;
        const int first = visible > 0 && selected >= visible ? selected - visible + 1 : 0;

        for (int i = first; i < count && i - first < visible; i++) {
            attrset(i == selected ? A_REVERSE : rows[i].enabled ? A_NORMAL : A_DIM);
            mvaddnstr(4 + i - first, 1, rows[i].label, COLS > 2 ? COLS - 2 : 0);
        }

        attrset(A_NORMAL);

        if (LINES > 2) {
            mvaddnstr(LINES - 2, 1, "Up/Down select | Enter apply | r refresh | Esc/q close", COLS > 2 ? COLS - 2 : 0);
        }

        refresh();

        if (reload) {
            count = load_interfaces(database, rows, status);
            selected = 0;
            reload = 0;

            continue;
        }

        const int key = getch();

        if (key == 27 || key == 'q' || key == 3) {
            break;
        }

        if (key == KEY_UP && selected > 0) {
            selected--;
        } else if (key == KEY_DOWN && selected + 1 < count) {
            selected++;
        } else if (key == 'r') {
            reload = 1;
        } else if ((key == '\n' || key == KEY_ENTER) && count > 0) {
            if (!rows[selected].enabled) {
                snprintf(status, sizeof status, "Choose an active, supported interface.");

                continue;
            }

            char command[80];
            char reply[CONTROL_REPLY_LEN];

            snprintf(command, sizeof command, selected == 0 ? "AUTO" : "SELECT %s", rows[selected].name);
            mvaddnstr(2, 1, "Applying capture source...", COLS > 2 ? COLS - 2 : 0);
            refresh();

            if (control_request(database, command, reply, sizeof reply) == -1) {
                snprintf(status, sizeof status, "Collector request failed: %.180s", strerror(errno));
            } else if (strncmp(reply, "OK\t", 3) == 0) {
                reload = 1;
            } else {
                snprintf(status, sizeof status, "%.240s", reply);
            }
        }
    }
}
