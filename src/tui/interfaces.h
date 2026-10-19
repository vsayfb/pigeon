#ifndef PIGEON_TUI_INTERFACES_H
#define PIGEON_TUI_INTERFACES_H

#include <signal.h>

/* Opens the interface selector; returns after Escape/q. Database remains
 * read-only. Capture changes are sent to the existing collector. */
void tui_interfaces(const char *database, const volatile sig_atomic_t *stopping);

#endif
