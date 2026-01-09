#include <assert.h>
#include <rbtree.h>
#include <stddef.h>
#include <stdio.h>

static rb_direction_t get_direction(rb_node_t* child) {
    return (child == child->parent->right) ? RB_DIRECTION_RIGHT : RB_DIRECTION_LEFT;
}

static rb_direction_t get_direction_relative(rb_node_t* child, rb_node_t* parent) {
    return (child == parent->right) ? RB_DIRECTION_RIGHT : RB_DIRECTION_LEFT;
}

static rb_direction_t opposite_direction(rb_direction_t direction) {
    return (direction == RB_DIRECTION_LEFT) ? RB_DIRECTION_RIGHT : RB_DIRECTION_LEFT;
}

static rb_node_t* get_node_child(rb_node_t* node, rb_direction_t direction) {
    if(direction == RB_DIRECTION_LEFT) {
        return node->left;
    } else {
        return node->right;
    }
}

static void set_node_child(rb_node_t* node, rb_direction_t direction, rb_node_t* child) {
    if(direction == RB_DIRECTION_LEFT) {
        node->left = child;
    } else {
        node->right = child;
    }
}

static bool safe_node_red_check(rb_node_t* node) {
    if(node == nullptr) { return false; }

    return node->color == RB_COLOR_RED;
}

static void replace_node(rb_tree_t* tree, rb_node_t* target, rb_node_t* new_node) {
    if(target->parent == nullptr) {
        assert(tree->root == target);
        tree->root = new_node;
    } else {
        set_node_child(target->parent, get_direction(target), new_node);
    }

    if(new_node != nullptr) new_node->parent = target->parent;
}

static rb_node_t* rotate(rb_tree_t* tree, rb_node_t* node, rb_direction_t direction) {
    rb_node_t* rotation_parent = node->parent;
    rb_node_t* new_root = get_node_child(node, opposite_direction(direction));

    set_node_child(node, opposite_direction(direction), get_node_child(new_root, direction));
    if(get_node_child(node, opposite_direction(direction)) != nullptr) { get_node_child(node, opposite_direction(direction))->parent = node; }

    set_node_child(new_root, direction, node);
    node->parent = new_root;

    new_root->parent = rotation_parent;
    if(rotation_parent != nullptr) {
        set_node_child(rotation_parent, get_direction_relative(node, rotation_parent), new_root);
    } else {
        tree->root = new_root;
    }

    return new_root;
}

static void rebalance_insert(rb_tree_t* tree, rb_node_t* node) {
    rb_node_t* parent = node->parent;
    if(parent == nullptr) return;

    do {
        if(!parent->color) return;

        rb_node_t* grandparent = parent->parent;

        if(grandparent == nullptr) {
            parent->color = RB_COLOR_BLACK;
            return;
        }

        rb_direction_t direction = get_direction(parent);
        rb_node_t* uncle = get_node_child(grandparent, opposite_direction(direction));
        if(uncle == nullptr || !uncle->color) {
            if(node == get_node_child(parent, opposite_direction(direction))) {
                rotate(tree, parent, direction);
                node = parent;
                parent = get_node_child(grandparent, direction);
            }

            rotate(tree, grandparent, opposite_direction(direction));
            parent->color = RB_COLOR_BLACK;
            grandparent->color = RB_COLOR_RED;
            return;
        }

        parent->color = RB_COLOR_BLACK;
        uncle->color = RB_COLOR_BLACK;
        grandparent->color = RB_COLOR_RED;
        node = grandparent;
    } while((parent = node->parent) != nullptr);

    tree->root->color = RB_COLOR_BLACK;
}

void rb_insert(rb_tree_t* tree, rb_node_t* node) {
    node->color = RB_COLOR_RED;
    node->left = nullptr;
    node->right = nullptr;
    node->parent = nullptr;

    rb_node_t* current = tree->root;
    rb_direction_t direction;

    size_t node_value = tree->value_of_node(node);
    while(current != nullptr) {
        node->parent = current;

        size_t current_value = tree->value_of_node(current);
        if(node_value < current_value) {
            direction = RB_DIRECTION_LEFT;
        } else {
            direction = RB_DIRECTION_RIGHT;
        }

        current = get_node_child(current, direction);
    }

    if(node->parent == nullptr) {
        tree->root = node;
        node->color = RB_COLOR_BLACK;
        return;
    }
    set_node_child(node->parent, direction, node);

    if(node->parent->parent == nullptr) return;

    rebalance_insert(tree, node);
}

void rb_remove(rb_tree_t* tree, rb_node_t* node) {
    assert(node != nullptr);
    bool original_is_red = safe_node_red_check(node);

    rb_node_t *target, *target_parent;
    if(node->left == nullptr) {
        target = node->right;
        target_parent = node->parent;
        replace_node(tree, node, target);
    } else if(node->right == nullptr) {
        target = node->left;
        target_parent = node->parent;
        replace_node(tree, node, target);
    } else {
        rb_node_t* successor = node->right;
        while(successor->left != nullptr) successor = successor->left;

        original_is_red = safe_node_red_check(successor);

        target = successor->right;
        if(successor->parent == node) {
            target_parent = successor;
        } else {
            target_parent = successor->parent;
            replace_node(tree, successor, target);
            successor->right = node->right;
            successor->right->parent = successor;
        }
        assert(successor->left == nullptr);

        replace_node(tree, node, successor);
        successor->left = node->left;
        successor->left->parent = successor;
        successor->color = safe_node_red_check(node);
    }

    assert(target_parent == nullptr || target == target_parent->left || target == target_parent->right);

    if(original_is_red) return;

    while(target != tree->root && !safe_node_red_check(target)) {
        if(target == target_parent->left) {
            rb_node_t* target_other = target_parent->right;
            if(safe_node_red_check(target_other)) {
                target_other->color = RB_COLOR_BLACK;
                target_parent->color = RB_COLOR_RED;
                rotate(tree, target_parent, RB_DIRECTION_LEFT);
                assert(target == target_parent->left);
                target_other = target_parent->right;
            }
            if(!safe_node_red_check(target_other->left) && !safe_node_red_check(target_other->right)) {
                target_other->color = RB_COLOR_RED;
                target = target_parent;
            } else {
                if(!safe_node_red_check(target_other->right)) {
                    target_other->left->color = RB_COLOR_BLACK;
                    target_other->color = RB_COLOR_RED;
                    rotate(tree, target_other, RB_DIRECTION_RIGHT);
                    target_other = target_parent->right;
                }
                target_other->color = safe_node_red_check(target_parent);
                target_parent->color = RB_COLOR_BLACK;
                target_other->right->color = RB_COLOR_BLACK;
                rotate(tree, target_parent, RB_DIRECTION_LEFT);
                target = tree->root;
            }
        } else {
            rb_node_t* target_other = target_parent->left;
            if(safe_node_red_check(target_other)) {
                target_other->color = RB_COLOR_BLACK;
                target_parent->color = RB_COLOR_RED;
                rotate(tree, target_parent, RB_DIRECTION_RIGHT);
                assert(target == target_parent->right);
                target_other = target_parent->left;
            }
            if(!safe_node_red_check(target_other->right) && !safe_node_red_check(target_other->left)) {
                target_other->color = RB_COLOR_RED;
                target = target_parent;
            } else {
                if(!safe_node_red_check(target_other->left)) {
                    target_other->right->color = RB_COLOR_BLACK;
                    target_other->color = RB_COLOR_RED;
                    rotate(tree, target_other, RB_DIRECTION_LEFT);
                    target_other = target_parent->left;
                }
                target_other->color = safe_node_red_check(target_parent);
                target_parent->color = RB_COLOR_BLACK;
                target_other->left->color = RB_COLOR_BLACK;
                rotate(tree, target_parent, RB_DIRECTION_RIGHT);
                target = tree->root;
            }
        }
        target_parent = target->parent;
    }
    if(target) target->color = RB_COLOR_BLACK;
}

rb_node_t* rb_find_first(rb_tree_t* tree) {
    rb_node_t* current = tree->root;
    if(current == nullptr) return nullptr;

    while(current->left != nullptr) {
        current = current->left;
    }

    return current;
}


rb_node_t* rb_find_exact(rb_tree_t* tree, size_t needle) {
    rb_node_t* current = tree->root;

    while(current != nullptr) {
        size_t value = tree->value_of_node(current);
        if(value == needle) return current;
        current = (needle > value) ? current->right : current->left;
    }

    return nullptr;
}

rb_node_t* rb_find_lower(rb_tree_t* tree, size_t needle) {
    rb_node_t* current = tree->root;
    rb_node_t* last_lower = nullptr;

    while(current != nullptr) {
        size_t value = tree->value_of_node(current);;
        if(value < needle) {
            last_lower = current;
            current = current->right;
        } else {
            current = current->left;
        }
    }

    return last_lower;
}

rb_node_t* rb_find_upper(rb_tree_t* tree, size_t needle) {
    rb_node_t* current = tree->root;
    rb_node_t* last_upper = nullptr;

    while(current != nullptr) {
        size_t value = tree->value_of_node(current);
        if(value < needle) {
            last_upper = current;
            current = current->right;
        } else {
            current = current->left;
        }
    }

    return last_upper;
}

rb_node_t* rb_find_within(rb_tree_t* tree, size_t needle) {
    rb_node_t* current = tree->root;
    assert(tree->length_of_node != nullptr);

     while(current != nullptr) {
        size_t start = tree->value_of_node(current);
        size_t end = start + tree->length_of_node(current);
        if(start <= needle && needle < end) { return current; }
        current = (needle >= end) ? current->right : current->left;
    }

    return nullptr;
}

size_t rb_find_first_gap(rb_tree_t* tree, size_t start, size_t end, size_t size) {
    assert(tree->length_of_node != nullptr);

    if(tree->root == nullptr) { return (start + size <= end) ? start : 0; }

    size_t current_pos = start;
    rb_node_t* node = tree->root;
    while(node->left != nullptr) { node = node->left; }
    while(node != nullptr) {
        size_t node_start = tree->value_of_node(node);
        size_t node_end = node_start + tree->length_of_node(node);

        if(current_pos + size <= node_start) { return current_pos; }

        current_pos = node_end;

        if(node->right != nullptr) {
            node = node->right;
            while(node->left != nullptr) { node = node->left; }
        } else {
            rb_node_t* parent = node->parent;
            while(parent != nullptr && node == parent->right) {
                node = parent;
                parent = parent->parent;
            }
            node = parent;
        }
    }
    if(current_pos + size <= end) { return current_pos; }

    return 0;
}
