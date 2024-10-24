#ifndef _CAP_REV_TREE_H_
#define _CAP_REV_TREE_H_

#include "cap.h"
#include <stdio.h>
#include <pthread.h>

#define CAP_REV_TREE_SIZE (65536 * 256)
#define _CAP_REV_NODE(tree, node_id) ((tree)->node_pool[assert(node_id < CAP_REV_TREE_SIZE), node_id])
// #define _CAP_REV_NODE_REUSABLE(tree, node_id) (_CAP_REV_NODE(tree, node_id).refcount == 0 && !_CAP_REV_NODE(tree, node_id).valid)
#define _CAP_REV_NODE_REUSABLE(tree, node_id) (_CAP_REV_NODE(tree, node_id).refcount == 0)

#define CAP_REV_MAX_THREADS 64

static const cap_rev_node_id_t CAP_REV_NODE_ID_NULL = -1;

struct CapRevNode {
    cap_rev_node_id_t prev, next;
    uint32_t depth;
    bool is_free;
    bool mutable;
    bool valid;
    bool linear; /* does invalidating this node necessitate hiding the data */
    uint32_t refcount; /* how many associated capabilities */
};

struct CapRevTree {
    struct CapRevNode node_pool[CAP_REV_TREE_SIZE];
    uint32_t alloced_n;
    cap_rev_node_id_t free_list;
    capregval_t *gprs[CAP_REV_MAX_THREADS];
};

typedef struct CapRevTree cap_rev_tree_t;

extern cap_rev_tree_t cr_tree;
extern pthread_mutex_t cr_tree_lock;

/* initialise the tree and create nodes for genesis caps */
void cap_rev_tree_init(cap_rev_tree_t *tree,
    cap_rev_node_id_t *pc_node, cap_rev_node_id_t *cap0_node, cap_rev_node_id_t *cap1_node);

/* returns the node id for the new revocation capability */
cap_rev_node_id_t cap_rev_tree_borrow(cap_rev_tree_t *tree, cap_rev_node_id_t node_id, bool mutable);
/* returns if the resulting capability should be linear; if false, the
capability should be uninitialised */
bool cap_rev_tree_revoke(cap_rev_tree_t *tree, cap_rev_node_id_t node_id, bool mutable);
/* returns the node id for the new capability */
cap_rev_node_id_t cap_rev_tree_split(cap_rev_tree_t *tree, cap_rev_node_id_t *node_id);

/* creates a new tree with a new node as its root */
cap_rev_node_id_t cap_rev_tree_create_lone_node(cap_rev_tree_t *tree, bool mutable);

void cap_rev_tree_release(cap_rev_tree_t *tree, cap_rev_node_id_t node_id);

inline static bool cap_rev_tree_check_valid(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id < tree->alloced_n);
    return _CAP_REV_NODE(tree, node_id).valid;
}

inline static bool cap_rev_tree_check_mutable(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id < tree->alloced_n);
    return _CAP_REV_NODE(tree, node_id).valid && _CAP_REV_NODE(tree, node_id).mutable;
}


inline static void cap_rev_tree_invalidate(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id < tree->alloced_n);
    _CAP_REV_NODE(tree, node_id).valid = false;
}

inline static void cap_rev_tree_update_refcount(cap_rev_tree_t *tree, cap_rev_node_id_t node_id, int32_t delta) {
    // fprintf(stderr, "R %u %d\n", node_id, delta);
    assert(node_id < tree->alloced_n && !_CAP_REV_NODE(tree, node_id).is_free);
    assert((~_CAP_REV_NODE(tree, node_id).refcount) > _CAP_REV_NODE(tree, node_id).refcount);
    // assert(_CAP_REV_NODE(tree, node_id).refcount != 0);
    _CAP_REV_NODE(tree, node_id).refcount += delta;
    // if(_CAP_REV_NODE_REUSABLE(tree, node_id)) {
    //     cap_rev_tree_release(tree, node_id);
    // }
}

inline static void cap_rev_tree_delin(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id < tree->alloced_n);
    _CAP_REV_NODE(tree, node_id).linear = false;
}

inline static void reg_overwrite(cap_rev_tree_t *tree, capregval_t *v) {
    // if (v->tag) {
    //     fprintf(stderr, "O %u\n", v->val.cap.rev_node_id);
    //     cap_rev_tree_update_refcount(tree, v->val.cap.rev_node_id, -1);
    // }
}

#endif
