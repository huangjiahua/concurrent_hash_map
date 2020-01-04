//
// Created by jiahua on 2019/10/14.
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <cassert>
#include <iostream>
#include <array>
#include <unordered_set>

#include "hash_map/fast_table.h"
#include "hash_map/thread.h"
#include "heavyhitter/GeneralLazySS.h"
#include "my_haz_ptr/haz_ptr.h"
#include "hash_map/pre_allocator.h"

namespace util {
size_t nextPowerOf2(size_t n) {
    size_t count = 0;

    // First n in the below condition
    // is for the case where n is 0
    if (n && !(n & (n - 1)))
        return n;

    while (n != 0) {
        n >>= 1ull;
        count += 1;
    }

    return 1ull << count;
}

size_t powerOf2(size_t n) {
    assert(n);
    size_t ret = 0;
    while (n != 1ull) {
        n >>= 1ull;
        ret++;
    }
    return ret;
}

struct ThreadIndexer {
    std::mutex mut_;
    std::array<bool, 128> place_holders_;


    ThreadIndexer() : place_holders_() {
        for (auto &i : place_holders_) {
            i = false;
        }
    }

    size_t Get() {
        constexpr size_t kImpossible = 1000;
        thread_local size_t l_idx{kImpossible};
        if (l_idx == kImpossible) {
            std::lock_guard<std::mutex> lk(mut_);
            for (size_t i = 0; i < place_holders_.size(); i++) {
                if (!place_holders_[i]) {
                    place_holders_[i] = true;
                    l_idx = i;
                    return (size_t) l_idx;
                }
            }
            std::cerr << "Thread count exceed limit" << std::endl;
            exit(1);
        }
        assert(l_idx != kImpossible);
        return (size_t) l_idx;
    }
};
}

enum class InsertType {
    DOES_NOT_EXIST,
    MUST_EXIST,
    ANY
};

enum class TreeNodeType {
    DATA_NODE,
    ARRAY_NODE,
    BUCKETS_NODE
};

class TreeNode {
public:
    virtual TreeNodeType Type() const = 0;

    virtual ~TreeNode() = default;
};


template<typename KeyType, typename ValueType>
class DataNode : public TreeNode {
    using Allocator = std::allocator<uint8_t>;
    using Mutex = std::mutex;
    using KVPair = std::pair<KeyType, ValueType>;
    template<typename T> using Atom = std::atomic<T>;
public:
public:
    DataNode(const KeyType &key, const ValueType &value) : kv_pair_{key, value} {}

    TreeNodeType Type() const override {
        return TreeNodeType::DATA_NODE;
    }

    std::pair<KeyType, ValueType> &GetValue() {
        return kv_pair_;
    }

    KVPair kv_pair_;
};

template<size_t LEN>
class ArrayNode : public TreeNode {
    using Allocator = std::allocator<uint8_t>;
    using Mutex = std::mutex;
    template<typename T, size_t SIZE> using Array = std::array<T, SIZE>;
    template<typename T> using Atom = std::atomic<T>;
public:
    TreeNodeType Type() const override {
        return TreeNodeType::ARRAY_NODE;
    }

    ArrayNode() {
        for (size_t i = 0; i < LEN; i++) {
            array_[i].store(nullptr);
        }
    }

    Array<Atom<TreeNode *>, LEN> array_;

    // LEN must be power of two
    size_t GetIdx(size_t h) const {
        return h & (LEN - 1);
    }
};

//namespace bucket {
//template<typename KeyType, typename ValueType>
//struct Node {
//    using KVPair = std::pair<KeyType, ValueType>;
//    using Allocator = std::allocator<uint8_t>;
//    template<typename T> using Atom = std::atomic<T>;
//    using key_type = KeyType;
//    using value_type = KVPair;
//
//    Node(const KeyType &k, const ValueType &v) : kv_pair_(k, v) {}
//
//    Node(const Node &node) : kv_pair_(node.kv_pair_) {}
//
//    const value_type &GetValue() const {
//        return kv_pair_;
//    }
//
//
//    KVPair kv_pair_;
//    Atom<Node *> next_{nullptr};
//};
//
//template<typename KeyType, typename ValueType>
//class alignas(128) Buckets {
//    using Allocator = std::allocator<uint8_t>;
//    template<typename T> using Atom = std::atomic<T>;
//    using InnerNode = Node<KeyType, ValueType>;
//    using BucketRoot = Atom<InnerNode *>;
//public:
//    static Buckets *Create(size_t count) {
//        auto buf = Allocator().allocate(sizeof(Buckets) + sizeof(BucketRoot) * count);
//        auto buckets = new(buf) Buckets();
//        for (size_t j = 0; j < count; j++) {
//            new(&buckets->root_[j]) BucketRoot;
//            buckets->root_[j].store(nullptr);
//        }
//        return buckets;
//    }
//
//    void Destory(size_t count) {
//        for (size_t j = 0; j < count; j++) {
//            root_[j].~BucketRoot();
//        }
//        this->~Buckets();
//        Allocator().deallocate((uint8_t *) this, sizeof(BucketRoot) * count + sizeof(Buckets));
//    }
//
//    ~Buckets() {
//    }
//
//    BucketRoot root_[0];
//};
//
//template<typename KeyType, typename ValueType, typename HashFn, typename KeyEqual>
//class BucketMap : public ::TreeNode {
//private:
//    using Allocator = std::allocator<uint8_t>;
//    using Mutex = std::mutex;
//    using BucketsT = Buckets<KeyType, ValueType>;
//    using InnerNode = Node<KeyType, ValueType>;
//    template<typename T> using Atom = std::atomic<T>;
//
//public:
//    using key_type = KeyType;
//    using value_type = std::pair<KeyType, ValueType>;
//
//    struct Iterator {
//        Iterator() = default;
//
//        explicit Iterator(std::nullptr_t) : hazptrs_(nullptr) {}
//
//        ~Iterator() = default;
//
//        void Set(InnerNode *node, BucketsT *buckets, size_t bucket_count, uint64_t idx) {
//            node_ = node;
//            buckets_ = buckets;
//            bucket_count_ = bucket_count;
//            idx_ = idx;
//        }
//
//        const value_type &operator*() const {
//            assert(node_);
//            return node_->GetValue();
//        }
//
//        const value_type *operator->() const {
//            assert(node_);
//            return &(node_->GetValue());
//        }
//
//        const Iterator &operator++() {
//            node_ = hazptrs_[2].get_protected(node_->next_);
//            hazptrs_[1].swap(hazptrs_[2]);
//            if (!node_) {
//                ++idx_;
//                Next();
//            }
//            return *this;
//        }
//
//        void Next() {
//            while (!node_) {
//                if (idx_ >= bucket_count_) {
//                    break;
//                }
//                assert(buckets_);
//                node_ = hazptrs_[1].get_protected(buckets_->root_[idx_]());
//                if (node_) {
//                    break;
//                }
//                ++idx_;
//            }
//        }
//
//        bool operator==(const Iterator &o) const {
//            return node_ == o.node_;
//        }
//
//        bool operator!=(const Iterator &o) const {
//            return !(*this == o);
//        }
//
//        Iterator &operator=(const Iterator &o) = delete;
//
//        Iterator &operator=(Iterator &&o) noexcept {
//            if (this != &o) {
//                hazptrs_ = std::move(o.hazptrs_);
//                node_ = std::exchange(o.node_, nullptr);
//                buckets_ = std::exchange(o.buckets_, nullptr);
//                bucket_count_ = std::exchange(o.bucket_count_, 0);
//                idx_ = std::exchange(o.idx_, 0);
//            }
//            return *this;
//        }
//
//        Iterator(const Iterator &o) = delete;
//
//        Iterator(Iterator &&o) noexcept
//                : hazptrs_(std::move(o.hazptrs_)),
//                  node_(std::exchange(o.node_, nullptr)),
//                  buckets_(std::exchange(o.buckets_, nullptr)),
//                  bucket_count_(std::exchange(o.bucket_count_, 0)),
//                  idx_(std::exchange(o.idx_, 0)) {}
//
//        hazptr_array<3> hazptrs_;
//        InnerNode *node_{nullptr};
//        BucketsT *buckets_{nullptr};
//        size_t bucket_count_{0};
//        uint64_t idx_{0};
//    };
//
//public:
//    BucketMap(
//            size_t initial_buckets,
//            float load_factor,
//            size_t max_size,
//            std::function<size_t(const KeyType &)> hasher = HashFn())
//            : load_factor_(load_factor), max_size_(max_size), hasher_(hasher) {
//        initial_buckets = util::nextPowerOf2(initial_buckets);
//        auto buckets = BucketsT::Create(initial_buckets);
//        buckets_.store(buckets);
//        bucket_count_.store(initial_buckets);
//        load_factor_nodes_ = load_factor_ * initial_buckets;
//    }
//
//    bool Find(Iterator &res, const KeyType &k) {
//        hazptr_holder<> &haz_curr = res.hazptrs_[1];
//        hazptr_holder<> &haz_next = res.hazptrs_[2];
//        size_t h = hasher_(k);
//        size_t bucket_count;
//        BucketsT *buckets;
//        GetBucketsPtrAndCount(buckets, bucket_count, res.hazptrs_[0]);
//
//        auto idx = GetIdx(bucket_count, h);
//        const Atom<InnerNode *> *prev = &buckets->root_[idx];
//        InnerNode *node = haz_curr.get_protected(*prev);
//        while (node) {
//            if (KeyEqual()(k, node->GetValue().first)) {
//                res.Set(node, buckets, bucket_count, idx);
//                return true;
//            }
//            node = haz_next.get_protected(node->next_);
//            haz_curr.swap(haz_next);
//        }
//        return false;
//    }
//
//    bool Insert(Iterator &it, const KeyType &k, const ValueType &v, InsertType type) {
//        return DoInsert(it, k, v, type, nullptr);
//    }
//
//    ::TreeNodeType Type() const override {
//        return ::TreeNodeType::BUCKETS_NODE;
//    }
//
//private:
//    void GetBucketsPtrAndCount(BucketsT *&buckets, size_t &count, hazptr_holder<> &holder) {
//        while (true) {
//            auto seq_lock = seq_lock_.load(std::memory_order_acquire);
//            count = bucket_count_.load(std::memory_order_acquire);
//            buckets = holder.get_protected(buckets_);
//            auto seq_lock2 = seq_lock_.load(std::memory_order_acquire);
//            if (!(seq_lock & 1) && (seq_lock == seq_lock2)) {
//                break;
//            }
//        }
//    }
//
//    size_t GetIdx(size_t bucket_count, size_t hash) {
//        return (hash & (bucket_count - 1));
//    }
//
//    bool DoInsert(Iterator &it, const KeyType &k, const ValueType &v, InsertType type, InnerNode *cur) {
//        size_t h = hasher_(k);
//        std::unique_lock<Mutex> g(mut_);
//
//        size_t bucket_count = bucket_count_.load(std::memory_order_relaxed);
//        auto buckets = buckets_.load(std::memory_order_relaxed);
//        if (size_ >= load_factor_nodes_ && type == InsertType::DOES_NOT_EXIST) {
//            Rehash(bucket_count << 1ull);
//            buckets = buckets_.load(std::memory_order_relaxed);
//            bucket_count = bucket_count_.load(std::memory_order_relaxed);
//        }
//
//        size_t idx = GetIdx(bucket_count, h);
//        assert(idx < bucket_count);
//        Atom<InnerNode *> *head = &buckets->root_[idx];
//        InnerNode *node = head->load(std::memory_order_relaxed);
//        InnerNode *head_node = node;
//        Atom<InnerNode *> *prev = head;
//        auto &haz_buckets = it.hazptrs_[0];
//        auto &haz_node = it.hazptrs_[1];
//        haz_buckets.reset(buckets);
//        while (node) {
//            if (KeyEqual()(k, node->GetValue().first)) {
//                // key found
//                it.Set(node, buckets, bucket_count, idx);
//                haz_node.reset(node);
//                if (type == InsertType::DOES_NOT_EXIST) {
//                    return false;
//                }
//
//                if (!cur) {
//                    cur = (InnerNode *) Allocator().allocate(sizeof(InnerNode));
//                    new(cur) InnerNode(k, v);
//                }
//
//                InnerNode *next = node->next_.load(std::memory_order_relaxed);
//                cur->next_.store(next, std::memory_order_relaxed);
//                prev->store(cur, std::memory_order_release);
//                g.unlock();
//                node->retire([](InnerNode *n) {
//                    Allocator().deallocate((uint8_t *) n, sizeof(InnerNode));
//                });
//                return true;
//            }
//            prev = &node->next_;
//            node = node->next_.load(std::memory_order_relaxed);
//        }
//        if (type != InsertType::DOES_NOT_EXIST && type != InsertType::ANY) {
//            haz_node.reset();
//            haz_buckets.reset();
//            return false;
//        }
//        // Node not found
//        if (size_ >= load_factor_nodes_ && type == InsertType::ANY) {
//            Rehash(bucket_count << 1ull);
//            buckets_.load(std::memory_order_relaxed);
//            bucket_count <<= 1ull;
//            haz_buckets.reset(buckets);
//            idx = GetIdx(bucket_count, h);
//            assert(idx < bucket_count);
//            head = &buckets->root_[idx];
//            head_node = head->load(std::memory_order_relaxed);
//        }
//
//        size_++;
//        if (!cur) {
//            assert(type == InsertType::DOES_NOT_EXIST || type == InsertType::ANY);
//            cur = (InnerNode *) Allocator().allocate(sizeof(InnerNode));
//            new(cur) InnerNode(k, v);
//        }
//        cur->next_.store(head_node, std::memory_order_relaxed);
//        assert(head);
//        head->store(cur, std::memory_order_release);
//        it.Set(cur, buckets, bucket_count, idx);
//        return true;
//    }
//
//    void Rehash(size_t bucket_count) {
//        BucketsT *buckets = buckets_.load(std::memory_order_relaxed);
//        BucketsT *new_buckets = BucketsT::Create(bucket_count);
//
//        load_factor_nodes_ = bucket_count * load_factor_;
//
//        size_t old_count = bucket_count_.load(std::memory_order_relaxed);
//        for (size_t i = 0; i < old_count; i++) {
//            Atom<InnerNode *> *bucket = &buckets->root_[i];
//            InnerNode *node = bucket->load(std::memory_order_relaxed);
//            if (!node) {
//                continue;
//            }
//            size_t h = hasher_(node->GetValue().first);
//            size_t idx = GetIdx(bucket_count, h);
//
//            InnerNode *last_run = node;
//            size_t last_idx = idx;
//            size_t count = 0;
//            InnerNode *last = node->next_.load(std::memory_order_relaxed);
//            for (; last != nullptr;
//                   last = last->next_.load(std::memory_order_relaxed)) {
//                size_t k = GetIdx(bucket_count, HashFn()(last->GetValue().first));
//                if (k != last_idx) {
//                    last_idx = k;
//                    last_run = last;
//                    count = 0;
//                }
//                count++;
//            }
//            new_buckets->root_[last_idx].store(last_run, std::memory_order_relaxed);
//
//            for (; node != last_run;
//                   node = node->next_.load(std::memory_order_relaxed)) {
//                InnerNode *new_node = (InnerNode *) Allocator().allocate(sizeof(InnerNode));
//                new(new_node) InnerNode(*node);
//                size_t k = GetIdx(bucket_count, HashFn()(node->GetValue().first));
//                Atom<InnerNode *> *prev_head = &new_buckets->root_[k];
//                new_node->next_.store(prev_head->load(std::memory_order_relaxed));
//                prev_head->store(new_node, std::memory_order_relaxed);
//            }
//        }
//
//        BucketsT *old_buckets = buckets_.load(std::memory_order_relaxed);
//        seq_lock_.fetch_add(1, std::memory_order_release);
//        bucket_count_.store(bucket_count, std::memory_order_release);
//        buckets_.store(new_buckets, std::memory_order_release);
//        seq_lock_.fetch_add(1, std::memory_order_release);
//        old_buckets->retire([old_count](BucketsT *b) {
//            b->Destory(old_count);
//        });
//    }
//
//private:
//    Mutex mut_;
//    float load_factor_;
//    size_t load_factor_nodes_;
//    size_t size_{0};
//    const size_t max_size_;
//    std::function<size_t(const KeyType &)> hasher_;
//
//    alignas(64) Atom<BucketsT *> buckets_{nullptr};
//    Atom<uint64_t> seq_lock_{0};
//    Atom<size_t> bucket_count_;
//};
//
//} // namespace bucket

struct ThreadHashMapStat {
    GeneralLazySS<size_t> ss_;
    size_t total_;

    ThreadHashMapStat() : ss_(0.00001), total_(0) {}

    size_t GetCount(size_t h) {
        auto p = ss_.find(h);
        if (p) {
            return p->getCount();
        }
        return 0;
    }

    void Record(size_t h) {
        ss_.put(h);
        total_++;
    }
};


template<typename KeyType, typename ValueType, typename HashFn, typename KeyEqual>
class ConcurrentHashMap {
    using Allocator = std::allocator<uint8_t>;
    using Mutex = std::mutex;
//    using BucketMapT = bucket::BucketMap<KeyType, ValueType, HashFn, KeyEqual>;
    template<typename T> using Atom = std::atomic<T>;
    using DataNodeT = DataNode<KeyType, ValueType>;

    static constexpr size_t kArrayNodeSize = 16;
    static constexpr size_t kArrayNodeSizeBits = 4;
    static constexpr size_t kHashWordLength = 64;
    static constexpr size_t kMaxDepth = 10;
    static constexpr uintptr_t kHighestBit = 0x8000000000000000ull;
    static constexpr uintptr_t kValidPtrField = 0x0000ffffffffffffull;
    using ArrayNodeT = ArrayNode<kArrayNodeSize>;
public:
    ConcurrentHashMap(size_t root_size, size_t max_depth, size_t thread_cnt = 32)
#ifndef DISABLE_FAST_TABLE
            : ft_(65536), stat_(0)
#endif
    {
        root_size_ = util::nextPowerOf2(root_size);
        root_bits_ = util::powerOf2(root_size_);
        thread_cnt = util::nextPowerOf2(thread_cnt);
        HazPtrInit(thread_cnt, 2);
        size_t remain = kHashWordLength - root_bits_;
        max_depth_ = std::min({kMaxDepth, remain / kArrayNodeSizeBits, max_depth});
        size_t shift = root_bits_ + 10 * kArrayNodeSizeBits;
        bucket_map_hasher_ = [shift](const KeyType &k) -> size_t {
            return (HashFn()(k) >> shift);
        };

        root_ = (Atom<TreeNode *> *) Allocator().allocate(sizeof(TreeNode *) * root_size_);
        for (size_t i = 0; i < root_size_; i++) {
            new(root_[i]) Atom<TreeNode *>;
            root_[i].store(nullptr);
        }
#ifndef DISABLE_FAST_TABLE
        stat_.reserve(64);
        for (size_t i = 0; i < 64; i++) {
            stat_.push_back(new ThreadHashMapStat);
        }
#endif
    }

#ifndef DISABLE_FAST_TABLE
    enum class AsyncInsertReturnCode {
        Ok,
        Error,
        Pending,
    };

    AsyncInsertReturnCode AsyncInsert(const KeyType &k, const ValueType &v, InsertType type = InsertType::ANY) {
        size_t h = HashFn()(k);
        size_t tid = Thread::id();
        ThreadHashMapStat *stat = stat_[tid];

        if (stat->total_ >= 5000000 && ft_.TryUpdate(h, k, v)) {
            return AsyncInsertReturnCode::Ok;
        }

        return AsyncInsertReturnCode::Pending;
    }
#endif


    bool Insert(const KeyType &k, const ValueType &v, InsertType type = InsertType::ANY) {
        size_t h = HashFn()(k);
#ifndef DISABLE_FAST_TABLE
        size_t tid = Thread::id();
        ThreadHashMapStat *stat = stat_[tid];
        if (stat->total_ < 5000000)
            stat->Record(h);

        if (stat->total_ >= 5000000 && ft_.TryUpdate(h, k, v)) {
            return true;
        }

        if (tid == 0 && stat->total_ == 5000000) {
            stat->total_++;
            Item<size_t> *p = stat->ss_.output(true);
            size_t k = 0;
            for (size_t i = 0; i < 65536; i++) {
                size_t hash = p[i].getItem();
                if (hash != std::numeric_limits<size_t>::max()) {
                    HazPtrHolder tmp_holder;
                    Atom<TreeNode *> *locate = nullptr;
                    auto elem = FindByHash(hash, tmp_holder, locate);
                    if (elem) {
                        bool r = ft_.CheckedInsert(hash, elem->kv_pair_.first, elem->kv_pair_.second);
                        if (r) {
                            k++;
                        }
                    }
                }
            }
        }
#endif
        DataNodeT *new_node = (DataNodeT *) Allocator().allocate(sizeof(DataNodeT));
        new(new_node) DataNodeT(k, v);
        std::unique_ptr<DataNodeT, std::function<void(DataNodeT *)>> ptr(new_node, [](DataNodeT *n) {
            n->~DataNode();
            Allocator().deallocate((uint8_t *) n, sizeof(DataNodeT));
        });

        auto res = DoInsert(h, k, ptr, type);
        return res;
    }

    bool Find(const KeyType &k, ValueType &v) {
        size_t h = HashFn()(k);

#ifndef DISABLE_FAST_TABLE
        {
            auto node = ft_.PinnedFind(h, k);
            if (node) {
                v = node->Value();
                return true;
            }
        }
#endif
        size_t n = 0;

        size_t idx = GetRootIdx(h);
        Atom<TreeNode *> *node_ptr = &root_[idx];
        TreeNode *node = nullptr;
        HazPtrHolder holder;
        while (true) {
            node = holder.Repin(*node_ptr, IsArrayNode, FilterValidPtr);

            if (!node) {
                return false;
            }

            switch (node->Type()) {
                case TreeNodeType::DATA_NODE: {
                    DataNodeT *d_node = static_cast<DataNodeT *>(node);
                    if (KeyEqual()(d_node->kv_pair_.first, k)) {
                        v = d_node->kv_pair_.second;
                        return true;
                    } else {
                        return false;
                    }
                }
                case TreeNodeType::ARRAY_NODE: {
                    n++;
                    ArrayNodeT *arr_node = static_cast<ArrayNodeT *>(node);
                    idx = GetNthIdx(h, n);
                    node_ptr = &arr_node->array_[idx];
                    continue;
                }
                case TreeNodeType::BUCKETS_NODE: {
                    std::cerr << "Not supported yet" << std::endl;
                    exit(1);
                }
            }
        }
    }

private:
    size_t GetRootIdx(size_t h) const {
        return (h & (root_size_ - 1));
    }

    size_t GetNthIdx(size_t h, size_t n) const {
        h >>= root_bits_;
        h >>= (n - 1) * kArrayNodeSizeBits;
        return (h & (kArrayNodeSize - 1));
    }

    static bool IsArrayNode(TreeNode *tnp) {
        return ((uintptr_t) tnp) & kHighestBit;
    }

    static TreeNode *FilterValidPtr(TreeNode *tnp) {
        return (TreeNode *) ((uintptr_t) tnp & kValidPtrField);
    }

    static TreeNode *MarkArrayNode(ArrayNodeT *anp) {
        return (TreeNode *) (((uintptr_t) anp) | kHighestBit);
    }

    DataNodeT *FindByHash(size_t h, HazPtrHolder &holder, Atom<TreeNode *> *&locate) {
        size_t n = 0;
        size_t curr_holder_idx = 0;

        size_t idx = GetRootIdx(h);
        Atom<TreeNode *> *node_ptr = &root_[idx];
        TreeNode *node = nullptr;
        while (true) {
            node = holder.Pin(*node_ptr, IsArrayNode, FilterValidPtr);

            if (!node) {
                return nullptr;
            }

            switch (node->Type()) {
                case TreeNodeType::DATA_NODE: {
                    DataNodeT *d_node = static_cast<DataNodeT *>(node);
                    locate = node_ptr;
                    return d_node;
                }
                case TreeNodeType::ARRAY_NODE: {
                    n++;
                    holder.Reset();
                    ArrayNodeT *arr_node = static_cast<ArrayNodeT *>(node);
                    idx = GetNthIdx(h, n);
                    node_ptr = &arr_node->array_[idx];
                    continue;
                }
                case TreeNodeType::BUCKETS_NODE: {
                    std::cerr << "Not supported yet" << std::endl;
                    exit(1);
                }
            }
        }
    }

    bool DoInsert(size_t h, const KeyType &k, std::unique_ptr<DataNodeT, std::function<void(DataNodeT *)>> &ptr,
                  InsertType type) {
        size_t n = 0;

        size_t idx = GetRootIdx(h);
        Atom<TreeNode *> *node_ptr = &root_[idx];
        TreeNode *node = nullptr;
        HazPtrHolder holder;
        while (true) {
            node = holder.Repin(*node_ptr, IsArrayNode, FilterValidPtr);

            if (!node) {
                if (type == InsertType::MUST_EXIST) {
                    return false;
                }

                bool result = node_ptr->compare_exchange_strong(node, (TreeNode *) ptr.get(),
                                                                std::memory_order_acq_rel);
                if (!result) {
                    continue;
                }
                ptr.release();
                return true;
            }

            switch (node->Type()) {
                case TreeNodeType::DATA_NODE: {
                    if (type == InsertType::DOES_NOT_EXIST) {
                        return false;
                    }
                    DataNodeT *d_node = static_cast<DataNodeT *>(node);
                    if (KeyEqual()(d_node->kv_pair_.first, k)) {
                        bool result = node_ptr->compare_exchange_strong(node, ptr.get(), std::memory_order_acq_rel);
                        if (!result) {
                            continue;
                        }
                        ptr.release();
                        HazPtrRetire(d_node);
                        return true;
                    } else {
                        if (n < max_depth_ - 1) {
                            std::unique_ptr<ArrayNodeT> tmp_arr_ptr(new ArrayNodeT);
                            size_t tmp_hash = HashFn()(d_node->kv_pair_.first);
                            size_t tmp_idx = GetNthIdx(tmp_hash, n + 1);
                            size_t next_idx = GetNthIdx(h, n + 1);

                            tmp_arr_ptr->array_[tmp_idx].store(node, std::memory_order_relaxed);

                            if (next_idx != tmp_idx) {
                                tmp_arr_ptr->array_[next_idx].store(ptr.get(), std::memory_order_relaxed);
                            }

                            bool result = node_ptr->compare_exchange_strong(node, MarkArrayNode(tmp_arr_ptr.get()),
                                                                            std::memory_order_acq_rel);

                            if (next_idx != tmp_idx) {
                                ptr.release();
                                tmp_arr_ptr.release();
                                return true;
                            }

                            if (result) {
                                n++;
                                size_t curr_idx = GetNthIdx(h, n);
                                node_ptr = &tmp_arr_ptr->array_[curr_idx];
                                tmp_arr_ptr.release();
                            }
                            continue;
                        } else {
                            std::cerr << "Not Implemented Yet" << std::endl;
                            exit(1);
                        }
                    }
                }
                case TreeNodeType::ARRAY_NODE: {
                    n++;
                    holder.Reset();
                    ArrayNodeT *arr_node = static_cast<ArrayNodeT *>(node);
                    size_t curr_idx = GetNthIdx(h, n);
                    node_ptr = &arr_node->array_[curr_idx];
                    continue;
                }
                case TreeNodeType::BUCKETS_NODE: {
                    std::cerr << "Not Implemented Yet" << std::endl;
                    exit(1);
                }
            }

        }
    }

private:
    Atom<TreeNode *> *root_{nullptr};
    std::function<size_t(const KeyType &)> bucket_map_hasher_;
#ifndef DISABLE_FAST_TABLE
    FastTable<KeyType, ValueType> ft_;
    std::vector<ThreadHashMapStat *> stat_;
#endif
    size_t root_size_{0};
    size_t root_bits_{0};
    size_t max_depth_{0};
};

