/* dfly_compat.h - DragonFly to OpenBSD compatibility */
#ifndef _DFLY_COMPAT_H_
#define _DFLY_COMPAT_H_

#include <sys/tree.h>

/* Map DragonFly RB macros to OpenBSD equivalents */
#define RB_GENERATE_SCAN(name, type, field) \
    RB_GENERATE(name, type, field, name##_cmp)

/* Implement RB_SCAN using RB_FOREACH */
#define RB_SCAN(name, head, cmp, callback, data) do { \
    struct type *elm; \
    RB_FOREACH(elm, name, head) { \
        if (cmp(elm, data) == 0) \
            callback(elm, data); \
    } \
} while (0)

#endif /* _DFLY_COMPAT_H_ */
