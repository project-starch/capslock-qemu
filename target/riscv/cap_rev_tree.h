#ifndef _CAP_REV_TREE_H_
#define _CAP_REV_TREE_H_

#include "cap.h"
#include <stdio.h>
#include <pthread.h>
#include <glib.h>

#define CAP_REV_TREE_SIZE (65536 * 256)
// #define _CAP_REV_NODE_REUSABLE(tree, node_id) (_CAP_REV_NODE(tree, node_id).refcount == 0 && !_CAP_REV_NODE(tree, node_id).valid)
#define _CAP_REV_NODE_REUSABLE(node) (node->refcount == 0)

#define CAP_REV_MAX_THREADS 128

typedef struct CapRevNodeRange {
    uintptr_t base;
    uintptr_t end;
} cap_rev_node_range_t;

struct CapRevNode {
    struct CapRevNode *parent, *child, *sibling;
    bool is_free;
    bool mutable;
    bool valid;
    bool is_unsafecell; /* does this node correspond to an UnsafeCell? */
    cap_rev_node_range_t range;
    uint32_t refcount; /* how many associated capabilities */
    struct CapRevNode *unsafecell_prev, *unsafecell_next;
};

typedef struct CapRevNode cap_rev_node_t;

struct CapRevTree {
    cap_rev_node_t node_pool[CAP_REV_TREE_SIZE];
    uint32_t alloced_n;
    cap_rev_node_t *free_list;
    capregval_t *gprs[CAP_REV_MAX_THREADS];
    GHashTable *unsafe_cell_subtrees; /* addr -> node */
};

typedef struct CapRevTree cap_rev_tree_t;

extern cap_rev_tree_t cr_tree;
extern pthread_mutex_t cr_tree_lock;

/* returns the node id for the new revocation capability */
cap_rev_node_t *cap_rev_tree_borrow(cap_rev_tree_t *tree, cap_rev_node_t *node, bool mutable,
    uintptr_t base, uintptr_t end, bool is_unsafecell);

/** access through the given node, returns whether the access should be allowed */
bool cap_rev_tree_access(cap_rev_tree_t *tree, cap_rev_node_t *node, bool is_write);

bool cap_rev_tree_revoke(cap_rev_tree_t *tree, cap_rev_node_t *node);

/* creates a new tree with a new node as its root */
cap_rev_node_t *cap_rev_tree_create_lone_node(cap_rev_tree_t *tree, bool mutable);

void cap_rev_tree_mark_unsafecell(cap_rev_tree_t *tree, cap_rev_node_t *node);

void cap_rev_tree_release(cap_rev_tree_t *tree, cap_rev_node_t *node);

inline static bool cap_rev_tree_check_valid(cap_rev_node_t *node) {
    assert(node != NULL);
    return node->valid;
}

inline static bool cap_rev_tree_check_mutable(cap_rev_node_t *node) {
    assert(node != NULL);
    return node->valid && node->mutable;
}


inline static void cap_rev_tree_invalidate(cap_rev_tree_t *tree, cap_rev_node_t *node) {
    assert(node != NULL);
    // fprintf(stderr, "Invaliding %u\n", node_id);
    node->valid = false;

    if (node->is_unsafecell) {
        // remove from unsafecell list
        cap_rev_node_t *prev = node->unsafecell_prev, *next = node->unsafecell_next;
        if(prev) {
            prev->unsafecell_next = next;
        } else {
            // new head
            if(next != NULL) {
                g_hash_table_insert(tree->unsafe_cell_subtrees, (gpointer)node->range.base, (gpointer)next);
            } else {
                // empty now
                g_hash_table_remove(tree->unsafe_cell_subtrees, (gconstpointer)node->range.base);
            }
        }
        if(next) {
            next->unsafecell_prev = prev;
        }
    }
}

inline static void cap_rev_tree_update_refcount(cap_rev_node_t *node, int32_t delta) {
    // fprintf(stderr, "R %u %d\n", node_id, delta);
    assert(node != NULL && !node->is_free);
    assert((~node->refcount) > node->refcount);
    // assert(_CAP_REV_NODE(tree, node_id).refcount != 0);
    node->refcount += delta;
    // if(_CAP_REV_NODE_REUSABLE(tree, node_id)) {
    //     cap_rev_tree_release(tree, node_id);
    // }
}

inline static void reg_overwrite(cap_rev_tree_t *tree, capregval_t *v) {
    // if (v->tag) {
    //     fprintf(stderr, "O %u\n", v->val.cap.rev_node_id);
    //     cap_rev_tree_update_refcount(tree, v->val.cap.rev_node_id, -1);
    // }
}

inline static void cap_rev_tree_update_refcount_cap(capfat_t *cap, int32_t delta) {
    for (int i = 0; i < CAP_MAX_PROVENANCE_N; i ++)
        if (cap->bounds[i].rev_node != NULL)
            cap_rev_tree_update_refcount(cap->bounds[i].rev_node, delta);
}

bool cap_bounds_collapse(cap_rev_tree_t *tree, capboundsfat_t *bounds, capaddr_t addr, capaddr_t size, bool *is_far_oob);

#endif
