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

typedef enum {
    CAP_REV_NODE_TYPE_REF = 0,
    CAP_REV_NODE_TYPE_RAW = 1,
    CAP_REV_NODE_TYPE_UNSAFECELL = 2
} cap_rev_node_type_t;

struct CapRevNode {
    struct CapRevNode *parent, *child, *sibling;
    bool is_free;
    bool mutable;
    bool valid;
    bool pinned;
    cap_rev_node_type_t ty;
    cap_rev_node_range_t range;
    uint32_t refcount; /* how many associated capabilities */
    uint32_t depth;
    uint64_t alloc_id;
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
    uintptr_t base, uintptr_t end);

/** access through the given node, returns whether the access should be allowed */
bool cap_rev_tree_access(cap_rev_tree_t *tree, cap_rev_node_t *node, cap_rev_node_range_t *range, bool is_write);

bool cap_rev_tree_revoke(cap_rev_tree_t *tree, cap_rev_node_t *node);

/* creates a new tree with a new node as its root */
cap_rev_node_t *cap_rev_tree_create_lone_node(cap_rev_tree_t *tree, bool mutable);

void cap_rev_tree_mark_unsafecell(cap_rev_tree_t *tree, cap_rev_node_t *node, cap_rev_node_type_t ty);

void cap_rev_tree_release(cap_rev_tree_t *tree, cap_rev_node_t *node);

inline static bool cap_rev_tree_check_valid(cap_rev_node_t *node) {
    if(node == NULL)
        return false;
    return node->valid;
}

inline static bool cap_rev_tree_check_mutable(cap_rev_node_t *node) {
    if(node == NULL)
        return false;
    return node->valid && node->mutable;
}


void cap_rev_tree_invalidate(cap_rev_tree_t *tree, cap_rev_node_t *node);

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

inline static void cap_bounds_clear(capfat_t *cap) {
    for(int i = 0; i < CAP_MAX_PROVENANCE_N; i ++)
        cap->bounds[i].rev_node = NULL;
}

inline static cap_rev_node_t *cap_rev_tree_find_root(cap_rev_node_t *node) {
    assert(node != NULL);
    cap_rev_node_t *cur;
    for(cur = node; cur->parent != NULL; cur = cur->parent);
    return cur;
}

inline static bool cap_rev_tree_is_unsafe_cell(cap_rev_node_t *node) {
    return node->ty == CAP_REV_NODE_TYPE_UNSAFECELL;
}

inline static bool cap_rev_tree_is_raw(cap_rev_node_t *node) {
    return node->ty == CAP_REV_NODE_TYPE_UNSAFECELL
        || node->ty == CAP_REV_NODE_TYPE_RAW;
}

inline static bool cap_rev_tree_is_ref(cap_rev_node_t *node) {
    return node->ty == CAP_REV_NODE_TYPE_REF;
}

#endif
