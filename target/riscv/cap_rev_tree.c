#include "cap_rev_tree.h"

static cap_rev_node_id_t _cap_rev_tree_alloc_node(cap_rev_tree_t *tree) {
    if(tree->alloced_n < CAP_REV_TREE_SIZE) {
        return tree->alloced_n ++;
    }
    if(tree->free_list != CAP_REV_NODE_ID_NULL) {
        cap_rev_node_id_t res = tree->free_list;
        tree->free_list = _CAP_REV_NODE(tree, res).next;
        return res;
    }
    return CAP_REV_NODE_ID_NULL;
}

static cap_rev_node_id_t _cap_rev_tree_dup_node_after(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id != CAP_REV_NODE_ID_NULL);
    assert(_CAP_REV_NODE(tree, node_id).valid);

    cap_rev_node_id_t new_node = _cap_rev_tree_alloc_node(tree);
    assert(new_node != CAP_REV_NODE_ID_NULL);

    _CAP_REV_NODE(tree, new_node).depth = _CAP_REV_NODE(tree, node_id).depth;
    _CAP_REV_NODE(tree, new_node).valid = true;
    _CAP_REV_NODE(tree, new_node).linear = true;
    _CAP_REV_NODE(tree, new_node).refcount = 1;

    cap_rev_node_id_t next = _CAP_REV_NODE(tree, node_id).next;
    _CAP_REV_NODE(tree, new_node).next = next;
    if(next != CAP_REV_NODE_ID_NULL) {
        _CAP_REV_NODE(tree, next).prev = new_node;
    }
    _CAP_REV_NODE(tree, new_node).prev = node_id;
    _CAP_REV_NODE(tree, node_id).next = new_node;

    return new_node;
}

// static cap_rev_node_id_t _cap_rev_tree_dup_node_before(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
//     assert(node_id != CAP_REV_NODE_ID_NULL);
//     assert(_CAP_REV_NODE(tree, node_id).valid);

//     cap_rev_node_id_t new_node = _cap_rev_tree_alloc_node(tree);
//     assert(new_node != CAP_REV_NODE_ID_NULL);

//     _CAP_REV_NODE(tree, new_node).depth = _CAP_REV_NODE(tree, node_id).depth;
//     _CAP_REV_NODE(tree, new_node).valid = true;
//     _CAP_REV_NODE(tree, new_node).linear = true;
//     _CAP_REV_NODE(tree, new_node).refcount = 1;

//     cap_rev_node_id_t prev = _CAP_REV_NODE(tree, node_id).prev;
//     _CAP_REV_NODE(tree, new_node).prev = prev;
//     if(prev != CAP_REV_NODE_ID_NULL) {
//         _CAP_REV_NODE(tree, prev).next = new_node;
//     }
//     _CAP_REV_NODE(tree, new_node).next = node_id;
//     _CAP_REV_NODE(tree, node_id).prev = new_node;

//     return new_node;
// }

cap_rev_node_id_t cap_rev_tree_create_lone_node(cap_rev_tree_t *tree) {
    cap_rev_node_id_t node = _cap_rev_tree_alloc_node(tree);
    _CAP_REV_NODE(tree, node).depth = 0;
    _CAP_REV_NODE(tree, node).refcount = 1;
    _CAP_REV_NODE(tree, node).prev = CAP_REV_NODE_ID_NULL;
    _CAP_REV_NODE(tree, node).next = CAP_REV_NODE_ID_NULL;
    _CAP_REV_NODE(tree, node).valid = true;
    _CAP_REV_NODE(tree, node).linear = true;
    return node;
}

void cap_rev_tree_init(cap_rev_tree_t *tree,
    cap_rev_node_id_t *pc_node, cap_rev_node_id_t *cap0_node, cap_rev_node_id_t *cap1_node)
{
    tree->alloced_n = 0;

    *pc_node = cap_rev_tree_create_lone_node(tree);
    *cap0_node = cap_rev_tree_create_lone_node(tree);
    *cap1_node = cap_rev_tree_create_lone_node(tree);
}


cap_rev_node_id_t cap_rev_tree_borrow(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    cap_rev_node_id_t new_node = _cap_rev_tree_dup_node_after(tree, node_id);
    _CAP_REV_NODE(tree, new_node).depth ++;
    return new_node;
}

cap_rev_node_id_t cap_rev_tree_split(cap_rev_tree_t *tree, cap_rev_node_id_t *node_id) {
    cap_rev_node_id_t node_a = _cap_rev_tree_dup_node_after(tree, *node_id);
    cap_rev_node_id_t node_b = _cap_rev_tree_dup_node_after(tree, *node_id);

    _CAP_REV_NODE(tree, node_a).depth ++;
    _CAP_REV_NODE(tree, node_b).depth ++;
    *node_id = node_a;

    return node_b;
}

bool cap_rev_tree_revoke(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id != CAP_REV_NODE_ID_NULL);
    uint32_t depth = _CAP_REV_NODE(tree, node_id).depth;
    cap_rev_node_id_t cur;
    bool retain_data = true;
    for(cur = _CAP_REV_NODE(tree, node_id).next;
        cur != CAP_REV_NODE_ID_NULL && _CAP_REV_NODE(tree, node_id).depth > depth;
        cur = _CAP_REV_NODE(tree, cur).next)
    {
        retain_data = retain_data && !_CAP_REV_NODE(tree, cur).linear;
        _CAP_REV_NODE(tree, cur).valid = false;
    }

    // remove the subtree
    _CAP_REV_NODE(tree, node_id).next = cur;
    if(cur != CAP_REV_NODE_ID_NULL) {
        _CAP_REV_NODE(tree, cur).prev = node_id;
    }

    return retain_data;
}

void cap_rev_tree_release(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(_CAP_REV_NODE_REUSABLE(tree, node_id));
    _CAP_REV_NODE(tree, node_id).next = tree->free_list;
    tree->free_list = node_id;
}
