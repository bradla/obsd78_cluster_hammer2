/* hammer_compat.h - OpenBSD compatibility for HAMMER2 */
#ifndef _HAMMER_COMPAT_H_
#define _HAMMER_COMPAT_H_

#include <sys/tree.h>

/* Function declarations */
void hammer2_chain_ref(hammer2_chain_t *chain);
void hammer2_chain_drop(hammer2_chain_t *chain);

/* RB tree compatibility macro (use carefully) */
#ifndef RB_SCAN
#define RB_SCAN(name, head, cmp, callback, data) do { \
    struct hammer2_chain *elm; \
    RB_FOREACH(elm, name, head) { \
        if (cmp == NULL || cmp(elm, data) == 0) \
            callback(elm, data); \
    } \
} while (0)
#endif

#endif /* _HAMMER_COMPAT_H_ */
