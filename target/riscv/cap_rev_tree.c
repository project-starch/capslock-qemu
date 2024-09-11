#include "cap_rev_tree.h"

static void _cap_rev_tree_gc(cap_rev_tree_t *tree) {
    int n;
    for(n = 0; n < CAP_REV_TREE_SIZE; n ++) {
        cap_rev_node_id_t cur = (cap_rev_node_id_t)n;
        while (cur != CAP_REV_NODE_ID_NULL && _CAP_REV_NODE_REUSABLE(tree, cur) && !_CAP_REV_NODE(tree, cur).is_free) {
            cap_rev_node_id_t nxt = _CAP_REV_NODE(tree, cur).next;
            cap_rev_node_id_t prev = _CAP_REV_NODE(tree, cur).prev;
            bool in_reg = false;
            int i;
            if(nxt != CAP_REV_NODE_ID_NULL && _CAP_REV_NODE(tree, nxt).depth > _CAP_REV_NODE(tree, cur).depth &&
                prev != CAP_REV_NODE_ID_NULL && _CAP_REV_NODE(tree, prev).depth >= _CAP_REV_NODE(tree, cur).depth) {
                break;
            }
            for (i = 1; i < 32; i ++) {
                if (tree->gprs[i].tag && tree->gprs[i].val.cap.rev_node_id == n) {
                    in_reg = true;
                    break;
                }
            }
            if(in_reg)
                break;
            // move this node to free list
            cap_rev_tree_release(tree, cur);
            cur = prev;
        }
    }
}

static cap_rev_node_id_t _cap_rev_tree_alloc_node(cap_rev_tree_t *tree) {
    if(tree->alloced_n < CAP_REV_TREE_SIZE) {
        return tree->alloced_n ++;
    }
    // free list is empty, now try recycling some nodes
    if(tree->free_list == CAP_REV_NODE_ID_NULL) {
        _cap_rev_tree_gc(tree);
    }
    if(tree->free_list != CAP_REV_NODE_ID_NULL) {
        cap_rev_node_id_t res = tree->free_list;
        tree->free_list = _CAP_REV_NODE(tree, res).next;
        _CAP_REV_NODE(tree, res).is_free = false;
        return res;
    }

    return CAP_REV_NODE_ID_NULL;
}

static cap_rev_node_id_t _cap_rev_tree_dup_node_after(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(node_id != CAP_REV_NODE_ID_NULL);
    // assert(_CAP_REV_NODE(tree, node_id).valid);

    cap_rev_node_id_t new_node = _cap_rev_tree_alloc_node(tree);
    assert(new_node != CAP_REV_NODE_ID_NULL);

    _CAP_REV_NODE(tree, new_node).depth = _CAP_REV_NODE(tree, node_id).depth;
    _CAP_REV_NODE(tree, new_node).valid = _CAP_REV_NODE(tree, node_id).valid;
    _CAP_REV_NODE(tree, new_node).linear = true;
    _CAP_REV_NODE(tree, new_node).mutable = _CAP_REV_NODE(tree, node_id).mutable;
    _CAP_REV_NODE(tree, new_node).refcount = 0;

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
//     _CAP_REV_NODE(tree, new_node).refcount = 0;

//     cap_rev_node_id_t prev = _CAP_REV_NODE(tree, node_id).prev;
//     _CAP_REV_NODE(tree, new_node).prev = prev;
//     if(prev != CAP_REV_NODE_ID_NULL) {
//         _CAP_REV_NODE(tree, prev).next = new_node;
//     }
//     _CAP_REV_NODE(tree, new_node).next = node_id;
//     _CAP_REV_NODE(tree, node_id).prev = new_node;

//     return new_node;
// }

cap_rev_node_id_t cap_rev_tree_create_lone_node(cap_rev_tree_t *tree, bool mutable) {
    cap_rev_node_id_t node = _cap_rev_tree_alloc_node(tree);
    _CAP_REV_NODE(tree, node).depth = 0;
    _CAP_REV_NODE(tree, node).refcount = 0;
    _CAP_REV_NODE(tree, node).prev = CAP_REV_NODE_ID_NULL;
    _CAP_REV_NODE(tree, node).next = CAP_REV_NODE_ID_NULL;
    _CAP_REV_NODE(tree, node).mutable = mutable;
    _CAP_REV_NODE(tree, node).valid = true;
    _CAP_REV_NODE(tree, node).linear = true;
    return node;
}

void cap_rev_tree_init(cap_rev_tree_t *tree,
    cap_rev_node_id_t *pc_node, cap_rev_node_id_t *cap0_node, cap_rev_node_id_t *cap1_node)
{
    tree->alloced_n = 0;

    *pc_node = cap_rev_tree_create_lone_node(tree, true);
    *cap0_node = cap_rev_tree_create_lone_node(tree, true);
    *cap1_node = cap_rev_tree_create_lone_node(tree, true);
}


cap_rev_node_id_t cap_rev_tree_borrow(cap_rev_tree_t *tree, cap_rev_node_id_t node_id, bool mutable) {
    if (mutable && !_CAP_REV_NODE(tree, node_id).mutable)
        return CAP_REV_NODE_ID_NULL;
    cap_rev_node_id_t new_node = _cap_rev_tree_dup_node_after(tree, node_id);
    _CAP_REV_NODE(tree, new_node).depth ++;
    _CAP_REV_NODE(tree, new_node).mutable = mutable;
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

bool cap_rev_tree_revoke(cap_rev_tree_t *tree, cap_rev_node_id_t node_id, bool mutable) {
    assert(node_id != CAP_REV_NODE_ID_NULL);
    uint32_t depth = _CAP_REV_NODE(tree, node_id).depth;
    cap_rev_node_id_t cur;
    bool retain_data = true;
    for(cur = _CAP_REV_NODE(tree, node_id).next;
        cur != CAP_REV_NODE_ID_NULL && _CAP_REV_NODE(tree, cur).depth > depth;
        cur = _CAP_REV_NODE(tree, cur).next)
    {
        retain_data = retain_data && !_CAP_REV_NODE(tree, cur).linear;
        if (mutable)
            _CAP_REV_NODE(tree, cur).valid = false;
        else
            _CAP_REV_NODE(tree, cur).mutable = false;
    }

    if (mutable) {
        // remove the subtree
        _CAP_REV_NODE(tree, node_id).next = cur;
        if(cur != CAP_REV_NODE_ID_NULL) {
            _CAP_REV_NODE(tree, cur).prev = node_id;
        }
    }

    return retain_data;
}

void cap_rev_tree_release(cap_rev_tree_t *tree, cap_rev_node_id_t node_id) {
    assert(_CAP_REV_NODE_REUSABLE(tree, node_id));
    cap_rev_node_id_t nxt = _CAP_REV_NODE(tree, node_id).next;
    cap_rev_node_id_t prev = _CAP_REV_NODE(tree, node_id).prev;
    if (prev != CAP_REV_NODE_ID_NULL) {
        _CAP_REV_NODE(tree, prev).next = nxt;
    }
    if (nxt != CAP_REV_NODE_ID_NULL) {
        _CAP_REV_NODE(tree, nxt).prev = prev;
    }
    _CAP_REV_NODE(tree, node_id).next = tree->free_list;
    tree->free_list = node_id;
    _CAP_REV_NODE(tree, node_id).is_free = true;
}
