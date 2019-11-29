//
// Created by jiahua on 2019/11/2.
//

#pragma once

#include <atomic>
#include <memory>

#include "my_haz_ptr/haz_ptr.h"

template<typename K, typename V>
class FastTableNode {
public:
    using KVPair = std::pair<K, V>;
    KVPair data_;
    size_t hash_;

    FastTableNode(size_t hash, const K &k, const V &v) : data_{k, v}, hash_{hash} {}

    size_t Hash() const {
        return hash_;
    }

    const K &Key() const {
        return data_.first;
    }

    const V &Value() const {
        return data_.second;
    }

    ~FastTableNode() = default;
};

template<typename N>
class alignas(128) FastTableSlot {
public:
    template<typename T> using Atom = std::atomic<T>;
    Atom<N *> atom_ptr_;

    FastTableSlot() : atom_ptr_{nullptr} {}

    ~FastTableSlot() = default;
};

template<typename KeyType, typename ValueType>
class FastTable {
private:
    template<typename T> using Atom = std::atomic<T>;
    using Node = FastTableNode<KeyType, ValueType>;
    using Slot = FastTableSlot<Node>;
    size_t size_;
    Slot *table_;
public:
    // size must be power of 2
    explicit FastTable(size_t size) : size_(size) {
        table_ = (Slot *) std::allocator<uint8_t>().allocate(sizeof(Slot) * size_);
        for (size_t i = 0; i < size_; i++) {
            new(table_ + i) Slot;
        }
    }

    ~FastTable() noexcept {
        for (size_t i = 0; i < size_; i++) {
            (table_ + i)->~Slot();
        }
        std::allocator<uint8_t>().deallocate((uint8_t *) table_, sizeof(Slot) * size_);
    }

    void Insert(size_t hash, const KeyType &key, const ValueType &value) {
        Node *node = new Node(hash, key, value);
        size_t idx = GetIdx(hash);
        Node *old = table_[idx].atom_ptr_.exchange(node);
        if (old) HazPtrRetire(old);
    }

    bool CheckedInsert(size_t hash, const KeyType &key, const ValueType &value) {
        size_t idx = GetIdx(hash);
        HazPtrHolder holder;
        Node *old_node = holder.Pin(table_[idx].atom_ptr_);
        if (old_node && (old_node->Hash() != hash || old_node->Key() != key)) {
            return false;
        }
        Node *node = new Node(hash, key, value);
        bool res = table_[idx].atom_ptr_.compare_exchange_strong(old_node, node, std::memory_order_acq_rel);
        if (!res) {
            delete node;
        } else {
            HazPtrRetire(old_node);
        }
        return res;
    }

    bool TryUpdate(size_t hash, const KeyType &key, const ValueType &value) {
        size_t idx = GetIdx(hash);
        HazPtrHolder holder;
        Node *old_node = holder.Pin(table_[idx].atom_ptr_);
        if (old_node && old_node->Hash() == hash && old_node->Key() == key) {
            Node *node = new Node(hash, key, value);
            bool res = table_[idx].atom_ptr_.compare_exchange_strong(old_node, node, std::memory_order_acq_rel);
            if (!res) {
                delete node;
            } else {
                HazPtrRetire(old_node);
            }
            return res;
        }
        return false;
    }

    Node *PinnedFind(size_t hash, const KeyType &key, HazPtrHolder &holder) {
        size_t idx = GetIdx(hash);
        Node *node = holder.Pin(table_[idx].atom_ptr_);
        if (!node || node->Key() != key) {
            if (node) {
                holder.Reset();
            }
            return nullptr;
        }
        return node;
    }

    size_t Size() const {
        return size_;
    }

private:
    inline size_t GetIdx(size_t hash) {
        return hash & (size_ - 1);
    }
};

