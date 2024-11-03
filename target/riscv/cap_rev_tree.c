#include "cap_rev_tree.h"
#include "glib.h"

cap_rev_tree_t cr_tree;
pthread_mutex_t cr_tree_lock = PTHREAD_MUTEX_INITIALIZER;

extern int cpu_count;

static void _cap_rev_tree_gc(cap_rev_tree_t *tree) {
    int n;
    int reusable_c = 0, free_c = 0, invalid_c = 0, to_release_c = 0;
    for(n = 0; n < CAP_REV_TREE_SIZE; n ++) {
        cap_rev_node_t *node = &tree->node_pool[n];
        if (_CAP_REV_NODE_REUSABLE(node))
            ++ reusable_c;
        if (node->is_free)
            ++ free_c;
        if (!node->valid)
            ++ invalid_c;
        assert(!node->is_free); // we shouldn't be doing GC if there's a free node
        if (_CAP_REV_NODE_REUSABLE(node) && !node->valid) {
            bool in_reg = false;
            int i, j, k;
            for (k = 0; k < CAP_REV_MAX_THREADS && !in_reg; k ++) {
                if (!tree->gprs[k])
                    continue;
                for (i = 1; i < 32 && !in_reg; i ++) {
                    if (!tree->gprs[k][i].tag)
                        continue;
                    for(j = 0; j < CAP_MAX_PROVENANCE_N; j ++) {
                        if (tree->gprs[k][i].val.cap.bounds[j].rev_node == node) {
                            in_reg = true;
                            break;
                        }
                    }
                }
            }
            if(!in_reg) {
                // move this node to free list
                ++ to_release_c;
                cap_rev_tree_release(tree, node);
            }
        }
    }
    // fprintf(stderr, "GC: reusable = %d, free = %d, invalid = %d, to release = %d\n",
    //     reusable_c, free_c, invalid_c, to_release_c);
}

static cap_rev_node_t *_cap_rev_tree_alloc_node(cap_rev_tree_t *tree) {
    if(tree->alloced_n < CAP_REV_TREE_SIZE) {
        return &tree->node_pool[tree->alloced_n ++];
    }
    // free list is empty, now try recycling some nodes
    if(tree->free_list == NULL) {
        _cap_rev_tree_gc(tree);
    }
    if(tree->free_list != NULL) {
        cap_rev_node_t *res = tree->free_list;
        tree->free_list = res->sibling;
        res->is_free = false;
        return res;
    }

    return NULL;
}


cap_rev_node_t *cap_rev_tree_create_lone_node(cap_rev_tree_t *tree, bool mutable) {
    static uint64_t alloc_counter;
    cap_rev_node_t *node = _cap_rev_tree_alloc_node(tree);
    node->refcount = 0;
    node->parent = NULL;
    node->sibling = NULL;
    node->child = NULL;
    node->mutable = mutable;
    node->valid = true;
    node->alloc_id = alloc_counter ++;
    node->depth = 0;
    node->pinned = false;
    return node;
}


void cap_rev_tree_mark_unsafecell(cap_rev_tree_t *tree, cap_rev_node_t *node, cap_rev_node_type_t ty) {
    if(node->ty == ty)
        return;
    node->ty = ty;
    if (ty == CAP_REV_NODE_TYPE_UNSAFECELL) {
        uintptr_t base = cap_rev_tree_find_root(node)->range.base;
        cap_rev_node_t *head = (cap_rev_node_t*)g_hash_table_lookup(tree->unsafe_cell_subtrees, (gconstpointer)base);
        node->unsafecell_prev = NULL;
        node->unsafecell_next = head;
        if(head != NULL) {
            head->unsafecell_prev = node;
        }
        g_hash_table_insert(tree->unsafe_cell_subtrees, (gpointer)base, (gpointer)node);
    }
}

void cap_rev_tree_invalidate(cap_rev_tree_t *tree, cap_rev_node_t *node) {
    assert(node != NULL);
    // fprintf(stderr, "Invalidating %p = %d, %lx %lx\n", node, node->ty, node->range.base, node->range.end);
    if(!node->valid)
        return;

    // if ((node->range.base & 0xffffff) == 0xd40) {
    //     fprintf(stderr, "Invalidated %lx %p\n", node->range.base, node);
    // }

    node->valid = false;

    if (cap_rev_tree_is_unsafe_cell(node)) {
        // remove from unsafecell list
        cap_rev_node_t *prev = node->unsafecell_prev, *next = node->unsafecell_next;
        if(prev) {
            prev->unsafecell_next = next;
        } else {
            // new head
            uintptr_t base = cap_rev_tree_find_root(node)->range.base;
            if(next != NULL) {
                g_hash_table_insert(tree->unsafe_cell_subtrees, (gpointer)base, (gpointer)next);
            } else {
                // empty now
                g_hash_table_remove(tree->unsafe_cell_subtrees, (gconstpointer)base);
            }
        }
        if(next) {
            next->unsafecell_prev = prev;
        }
    }
}



cap_rev_node_t *cap_rev_tree_borrow(cap_rev_tree_t *tree, cap_rev_node_t *node, bool mutable,
        uintptr_t base, uintptr_t end) {
    assert(node->valid && "Borrowing must be performed on a valid capability!");
    cap_rev_node_t *new_node = _cap_rev_tree_alloc_node(tree);
    assert(new_node && "Failed to allocate a new node for borrow!");
    new_node->range.base = base;
    new_node->range.end = end;
    new_node->depth = node->depth + 1;
    new_node->alloc_id = node->alloc_id;
    new_node->mutable = mutable;

    // connects the new node
    new_node->parent = node;
    new_node->is_free = false;
    new_node->refcount = 0;
    new_node->child = NULL;
    new_node->sibling = node->child;
    new_node->valid = true;
    new_node->ty = CAP_REV_NODE_TYPE_REF;
    new_node->pinned = false;
    node->child = new_node;

    return new_node;
}

void cap_rev_tree_release(cap_rev_tree_t *tree, cap_rev_node_t *node) {
    assert(_CAP_REV_NODE_REUSABLE(node));
    assert(!node->is_free);
    assert(!node->valid);

    node->sibling = tree->free_list;
    tree->free_list = node;
    node->is_free = true;
}


// subtree_root itself excluded
static void _invalidate_subtree(cap_rev_tree_t *tree, cap_rev_node_t *subtree_root) {
    if (!subtree_root->valid)
        return;
    // fprintf(stderr, "Subtree %p %d\n", subtree_root, subtree_root->is_unsafecell);
    static GQueue stack = G_QUEUE_INIT;
    g_queue_push_head(&stack, subtree_root);
    while (!g_queue_is_empty(&stack)) {
        cap_rev_node_t *cur = (cap_rev_node_t*)g_queue_pop_head(&stack);
        assert(cur);
        for (cap_rev_node_t *child = cur->child; child != NULL; child = child->sibling) {
            if(!child->valid)
                continue;
            cap_rev_tree_invalidate(tree, child);
            g_queue_push_head(&stack, child);
        }
    }
    subtree_root->child = NULL;
}

static inline bool range_overlaps(cap_rev_node_range_t *a, cap_rev_node_range_t *b) {
    return !(a->end <= b->base || b->end <= a->base);
}

// subtree_root itself and the subtree at except are excluded
static void _invalidate_subtree_overlap(cap_rev_tree_t *tree, cap_rev_node_t *subtree_root,
    cap_rev_node_t *except, cap_rev_node_range_t *range, bool skip_raw_children, bool mutable_ref_only) {
    if (!subtree_root->valid)
        return;
    // fprintf(stderr, "Subtree overlap %p %lx %lx %d\n", subtree_root, subtree_root->range.base, subtree_root->range.end, subtree_root->ty);

    cap_rev_node_t *new_child = NULL, *nxt;
    for(cap_rev_node_t *child = subtree_root->child; child != NULL; child = nxt) {
        nxt = child->sibling;
        if(!child->valid)
            continue;
        bool keep_child = true;
        if (child != except && !child->pinned && range_overlaps(range, &child->range)) {
            // remove this child and invalidate all nodes inside
            // fprintf(stderr, "Oops %p %lx %lx\n", child, child->range.base, child->range.end);
            if(mutable_ref_only) {
                if (child->mutable) {
                    if (cap_rev_tree_is_ref(child)) {
                        _invalidate_subtree(tree, child);
                        keep_child = false;
                    } else {
                        _invalidate_subtree_overlap(tree, child, NULL, range, false, true);
                    }
                }
            } else {
                _invalidate_subtree(tree, child);
                if (!skip_raw_children || !cap_rev_tree_is_raw(child)) {
                    keep_child = false;
                }
            }
        }
        if (keep_child) {
            // keep this child
            child->sibling = new_child;
            new_child = child;
        } else {
            cap_rev_tree_invalidate(tree, child);
        }
    }
    subtree_root->child = new_child;
}

// invalidate whole subtree including the root
bool cap_rev_tree_revoke(cap_rev_tree_t *tree, cap_rev_node_t *node) {
    if (!node->valid)
        return false;
    assert(node->parent == NULL); /* this only supports root nodes */
    _invalidate_subtree(tree, node);
    cap_rev_tree_invalidate(tree, node);

    return true;
}

bool cap_rev_tree_access(cap_rev_tree_t *tree, cap_rev_node_t *node, cap_rev_node_range_t *range, bool is_write) {
    // if (!node->valid || (is_write && !node->mutable))
    if (!node->valid)
        return false;
    if (is_write) {
        // fprintf(stderr, "Access %lx %lx node %p = %d, %lx, %lx\n", range->base, range->end, node, node->ty,
            // node->range.base, node->range.end);
        // for(cap_rev_node_t *cur = node; cur != NULL; cur = cur->parent) {
        //     fprintf(stderr, "> %p: %d %d %lx %lx\n", cur, cur->valid, cur->ty,
        //         cur->range.base, cur->range.end);
        // }
        // invalidate all aliasing nodes that are not parents
        // _invalidate_subtree(tree, node);

        /* Do different things depending on the pointer type */
        // bool skip_raw_children = false;
        // switch (node->ty) {
        //     CAP_REV_NODE_TYPE_REF:
        //         break;
        //     CAP_REV_NODE_TYPE_UNSAFECELL: /* UnsafeCell itself is raw */
        //     CAP_REV_NODE_TYPE_RAW:
        //         skip_raw_children = true;
        // }
        _invalidate_subtree_overlap(tree, node, NULL, range, false, false);
        cap_rev_node_t *cur;
        for(cur = node; cur->parent != NULL && !cap_rev_tree_is_unsafe_cell(cur); cur = cur->parent) {
            _invalidate_subtree_overlap(tree, cur->parent, cur, range,
                /* skip raw siblings */ cap_rev_tree_is_raw(cur), false);
        }
        if (cap_rev_tree_is_unsafe_cell(cur)) {
            // Ok this is UnsafeCell, we don't continue invalidation in ancestors, instead, we look at all
            // subtrees associated with this UnsafeCell
            cap_rev_node_t *head;
            // pin ancestors so they are not invalidated if they happen to be UnsafeCells at the same location
            for(head = cur->parent; head != NULL; head = head->parent) {
                head->pinned = true;
            }
            for(head = cur->unsafecell_next; head != NULL; head = head->unsafecell_next) {
                // fprintf(stderr, "UnsafeCell %p\n", head);
                _invalidate_subtree_overlap(tree, head, NULL, range, false, false);
            }
            for(head = cur->unsafecell_prev; head != NULL; head = head->unsafecell_prev) {
                // fprintf(stderr, "UnsafeCell %p\n", head);
                _invalidate_subtree_overlap(tree, head, NULL, range, false, false);
            }
            // unpin ancestors
            for(head = cur->parent; head != NULL; head = head->parent) {
                head->pinned = false;
            }

            // continue to the root to invalidate aliasing mutable references
            for(; cur->parent != NULL; cur = cur->parent) {
                bool mutable_ref_only = cur->parent->parent != NULL;
                _invalidate_subtree_overlap(tree, cur->parent, cur, range,
                    cap_rev_tree_is_raw(cur), mutable_ref_only);
            }

        }
    }
    // no need to do anything for read

    return true;
}

bool cap_bounds_collapse(cap_rev_tree_t *tree, capboundsfat_t *bounds, capaddr_t addr, capaddr_t size, bool *is_far_oob) {
    bool _is_far_oob = true;
    int i;
    for(i = 0; i < CAP_MAX_PROVENANCE_N; i ++) {
        if (bounds[i].rev_node != NULL &&
                cap_in_bounds(&bounds[i], addr, (capaddr_t)size))
            break;
        if (bounds[i].rev_node != NULL && !cap_is_far_oob(&bounds[i], addr))
            _is_far_oob = false;
    }
    if(i < CAP_MAX_PROVENANCE_N) {
        _is_far_oob = false;
        for(int j = i; j < CAP_MAX_PROVENANCE_N; j ++) {
            if (bounds[j].rev_node != NULL &&
                cap_in_bounds(&bounds[j], addr, (capaddr_t)size) &&
                (bounds[j].rev_node->alloc_id > bounds[i].rev_node->alloc_id
                || (
                    bounds[j].rev_node->alloc_id == bounds[i].rev_node->alloc_id &&
                    (
                        bounds[j].rev_node->depth > bounds[i].rev_node->depth
                        || (
                            bounds[j].rev_node->depth == bounds[i].rev_node->depth
                            && cap_rev_tree_check_valid(bounds[j].rev_node)
                        )
                    )
                ))
            )
                i = j;
        }
    }
    // if(i >= CAP_MAX_PROVENANCE_N && !_is_far_oob) {
    //     fprintf(stderr, "Oops %lx %lx\n", addr, (capaddr_t)size);
    //     for(int j = 0; j < CAP_MAX_PROVENANCE_N; j ++) {
    //         fprintf(stderr, "Bounds: %lx %lx %lx %d %d\n", bounds[j].base, bounds[j].end,
    //             cap_distance(&bounds[j], addr), bounds[j].rev_node != NULL,
    //             cap_in_bounds(&bounds[j], addr, (capaddr_t)size));
    //     }
    // }
    if(i < CAP_MAX_PROVENANCE_N) {
        bounds[0] = bounds[i];
        for(int j = 1; j < CAP_MAX_PROVENANCE_N; j ++)
            bounds[j].rev_node = NULL;
    } else if (_is_far_oob)
        for(int j = 0; j < CAP_MAX_PROVENANCE_N; j ++)
            bounds[j].rev_node = NULL;
    if(is_far_oob)
        *is_far_oob = _is_far_oob;
    return i < CAP_MAX_PROVENANCE_N;
}
