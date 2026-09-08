#include "../include/locals.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    Locals l;

    /* Churn: repeatedly fill to capacity with a mix of short/long keys,
     * remove from various positions, refill. Runs under ASan to catch
     * any leaked heap key or any read of the wrong union member. */
    for (int round = 0; round < 50; round++) {
        locals_init(&l, 0);
        char bufs[LOCALS_INLINE_CAPACITY][80];
        for (int i = 0; i < LOCALS_INLINE_CAPACITY; i++) {
            if ((i + round) % 3 == 0)
                snprintf(bufs[i], sizeof(bufs[i]), "k%d_%d", i, round); /* short */
            else
                snprintf(bufs[i], sizeof(bufs[i]),
                         "dynamic_long_key_round_%d_index_%d_padding_bytes", round, i); /* long */
            assert(locals_setvalue(&l, bufs[i], (void*)(intptr_t)(i + 1), NULL));
        }

        /* Remove and re-add every entry, forcing each slot to actually
         * free its previous key (inline or heap) and allocate/inline the
         * new one — exercises LocalsKeyDestroyAt at every index. */
        for (int i = 0; i < LOCALS_INLINE_CAPACITY; i++) {
            locals_remove(&l, bufs[i]);
            assert(locals_setvalue(&l, bufs[i], (void*)(intptr_t)(100 + i), NULL));
        }

        /* Remove every other entry (forces shifts across inline/heap boundary). */
        for (int i = 0; i < LOCALS_INLINE_CAPACITY; i += 2) {
            locals_remove(&l, bufs[i]);
        }
        for (int i = 1; i < LOCALS_INLINE_CAPACITY; i += 2) {
            assert(locals_getvalue(&l, bufs[i]) != NULL);
        }

        locals_reset(&l);
    }

    /* Same-slot inline<->heap churn: repeatedly set a short key, remove it,
     * set a long key, remove it — exercises the union tag flipping in
     * place many times over on what is likely the same backing memory. */
    locals_init(&l, 0);
    for (int i = 0; i < 200; i++) {
        char k[80];
        if (i % 2 == 0) {
            snprintf(k, sizeof(k), "short%d", i);
        } else {
            snprintf(k, sizeof(k), "this_is_a_much_longer_dynamically_built_key_%d", i);
        }
        assert(locals_setvalue(&l, k, (void*)1, NULL));
        assert(locals_getvalue(&l, k) == (void*)1);
        locals_remove(&l, k);
        assert(locals_getvalue(&l, k) == NULL);
    }

    return 0;
}
