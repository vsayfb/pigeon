#include "app/app_internal.h"

#include <errno.h>

struct app_snapshot *app_snapshot_read(void) {
    errno = ENOSYS;

    return NULL;
}
