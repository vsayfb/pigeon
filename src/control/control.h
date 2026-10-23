#ifndef PIGEON_CONTROL_H
#define PIGEON_CONTROL_H

#include <stddef.h>
#include <sys/types.h>

#define CONTROL_PATH_LEN 108
#define CONTROL_REPLY_LEN 16384

/* Linux local stream protocol: one newline-terminated LIST, STATUS, STOP, AUTO, or
 * SELECT <interface>, CLEAR, or DELETE <hex-identity> request per connection. Reply ends at EOF. First line
 * is OK<TAB>current<TAB>auto|manual, or ERROR<TAB>reason. LIST adds rows:
 * name<TAB>active|inactive<TAB>supported|unsupported|unavailable.
 * STOP requests graceful shutdown; socket removal follows the final store flush.
 * CLEAR/DELETE remove persisted history and pre-deletion in-memory traffic. */
struct control_server;
typedef void (*control_handler)(const char *request, char *reply, size_t capacity, void *user);

int control_path(const char *database, char out[CONTROL_PATH_LEN]);
struct control_server *control_server_open(const char *database, uid_t owner);
void control_server_poll(struct control_server *server, control_handler handler, void *user);
void control_server_close(struct control_server *server);

/* Bounded synchronous client for the terminal's interface dialog. */
int control_request(const char *database, const char *request, char *reply, size_t capacity);

#endif
