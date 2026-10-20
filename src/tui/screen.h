#ifndef PIGEON_TUI_SCREEN_H
#define PIGEON_TUI_SCREEN_H

#include "tui/model.h"

#define TUI_KEY_QUIT 1
#define TUI_KEY_REFRESH 2
#define TUI_KEY_INTERFACES 4

#define TUI_BRAND_BLUE 4
#define TUI_BRAND_TEAL 5

struct tui_screen {
    int focus;                /* live, top conversations, applications, new endpoints */
    size_t selected[4];
    int column_scroll[2];     /* independent conversation table offsets */
    int browsing;             /* hold focused list membership/order during navigation */
    int paused;
    int searching;
    int details;
    int help;
    size_t modal_scroll;
    char draft[TUI_SEARCH_LEN];
};

/* Draws within the current terminal dimensions; external strings are rendered
 * as printable ASCII. All snapshot/options/state pointers are borrowed. */
void tui_screen_draw(const struct tui_snapshot *snapshot, const struct tui_options *options,
                       const struct tui_screen *state, const char *path,
                       const char *error, int64_t now);

/* Handles a curses key; returns a combination of TUI_KEY_* flags. */
int tui_screen_key(int key, const struct tui_snapshot *snapshot,
                    struct tui_options *options, struct tui_screen *state);

/* Holds the focused list while browsing, updating matching rows from next.
 * Both snapshots are mutable work buffers. Missing live samples lose their
 * rate validity; historical counters remain available until browsing ends. */
void tui_screen_hold_list(struct tui_snapshot *old, struct tui_snapshot *next,
                          const struct tui_screen *state);

/* Preserves selection identity across refreshes when the selected key/IP
 * remains in a list; otherwise clamps its previous index to the new size. */
void tui_screen_reselect(const struct tui_snapshot *old, const struct tui_snapshot *next,
                          struct tui_screen *state);

#endif
