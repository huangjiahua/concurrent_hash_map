#include <cstdint>

#include <utility>
#include <iostream>
#include <algorithm>

#include "concurrent_dict.h"
#include "my_haz_ptr/haz_ptr.h"

ENABLE_LOCAL_DOMAIN

size_t next_power_of_2(size_t n) {
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

size_t power_of_2(size_t n) {
    assert(n);
    size_t ret = 0;
    while (n != 1ull) {
        n >>= 1ull;
        ret++;
    }
    return ret;
}

constexpr uint32_t kHashSeed = 7079;

uint64_t MurmurHash64A(const void *key, size_t len) {
    const uint64_t m = 0xc6a4a7935bd1e995ull;
    const size_t r = 47;
    uint64_t seed = kHashSeed;

    uint64_t h = seed ^(len * m);

    const auto *data = (const uint64_t *) key;
    const uint64_t *end = data + (len / 8);

    while (data != end) {
        uint64_t k = *data++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const auto *data2 = (const unsigned char *) data;

    switch (len & 7ull) {
        case 7:
            h ^= uint64_t(data2[6]) << 48ull;
        case 6:
            h ^= uint64_t(data2[5]) << 40ull;
        case 5:
            h ^= uint64_t(data2[4]) << 32ull;
        case 4:
            h ^= uint64_t(data2[3]) << 24ull;
        case 3:
            h ^= uint64_t(data2[2]) << 16ull;
        case 2:
            h ^= uint64_t(data2[1]) << 8ull;
        case 1:
            h ^= uint64_t(data2[0]);
            h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h;
}

size_t MurmurHashSlice(const concurrent_dict::Slice &slice) {
    return MurmurHash64A(slice.data(), slice.size());
}

enum class TreeNodeType {
    DATA_NODE,
    ARRAY_NODE,
    BUCKETS_NODE
};

struct TreeNode {
    static constexpr uintptr_t kValidPtrField = 0x0000ffffffffffffull;
public:
    virtual TreeNodeType Type() const = 0;

    virtual ~TreeNode() = default;

    static TreeNode *FilterValidPtr(TreeNode *tnp) {
        return (TreeNode *) ((uintptr_t) tnp & kValidPtrField);
    }
};

struct DataNode : TreeNode {
    template<typename T> using Atom = std::atomic<T>;
    using Allocator = std::allocator<uint8_t>;
    using Slice = concurrent_dict::Slice;

    TreeNodeType Type() const override { return TreeNodeType::DATA_NODE; }

    DataNode(const Slice &k, const Slice &v) :
            capacity_(k.size() + v.size()), key_size_(k.size()), val_size_(v.size()), seq_lock_(0) {
        memcpy(data_, k.data(), k.size());
        memcpy(data_ + k.size(), v.data(), v.size());
    }

    Slice Key() { return Slice(data_, key_size_); }

    Slice Value() { return Slice(data_ + key_size_, val_size_); }

    void CopyValue(std::string &buf) {
        uint32_t seq;
        do {
            do {
                seq = seq_lock_.load(std::memory_order_acquire);
            } while (seq & 1u);
            size_t n = std::min((size_t) val_size_, capacity_ - (size_t) key_size_);
            buf.resize(n, ' ');
            buf.replace(0, n, data_ + key_size_, n);
        } while (seq_lock_.load(std::memory_order_acquire) != seq);
    }

    bool UpdateValue(const Slice &v) {
        // capacity_ and key_size_ are constants, so it is thread-safe to
        // access them
        if (v.size() > capacity_ - key_size_) {
            return false;
        }
        uint32_t seq;
        bool res;
        int fail = 5;
        do {
            if (!(fail--)) {
                return false;
            }

            do {
                seq = seq_lock_.load(std::memory_order_acquire);
            } while (seq & 1u);
            res = seq_lock_.compare_exchange_strong(seq, seq + 1, std::memory_order_acq_rel);
        } while (!res);
        // now the lock is locked
        memcpy((void *) (data_ + key_size_), v.data(), v.size());
        assert(!(seq & 1u));
        seq_lock_.store(seq + 2, std::memory_order_release);
        val_size_ = v.size();
        return true;
    }

    static DataNode *NewDataNode(const Slice &k, const Slice &v) {
        size_t total = k.size() + v.size();
        auto ret = (DataNode *) Allocator().allocate(sizeof(DataNode) + total);
        new(ret) DataNode(k, v);
        return ret;
    }

    void Free() {
        Allocator().deallocate((uint8_t *) this, sizeof(*this) + capacity_);
    }

    const size_t capacity_;
    const uint32_t key_size_;
    uint32_t val_size_;
    Atom<uint32_t> seq_lock_;
    char data_[1]{};
};

struct ArrayNode : TreeNode {
    template<typename T> using Atom = std::atomic<T>;
    using Allocator = std::allocator<uint8_t>;

    static constexpr size_t kArrayNodeLen = 16;
    static constexpr size_t kArrayNodeSizeBits = 4;

    TreeNodeType Type() const override { return TreeNodeType::ARRAY_NODE; }

    static constexpr size_t byte_size() { return sizeof(ArrayNode) + kArrayNodeLen * sizeof(Atom<TreeNode *>); }

    static ArrayNode *NewArrayNode() {
        auto ret = (ArrayNode *) Allocator().allocate(byte_size());
        for (size_t j = 0; j < kArrayNodeLen; j++) {
            ret->array_[j].store(nullptr, std::memory_order_release);
        }
        new(ret) ArrayNode;
        return ret;
    }

    void Free() {
        for (size_t j = 0; j < kArrayNodeLen; j++) {
            array_[j].~Atom<TreeNode *>();
        }
        Allocator().deallocate((uint8_t *) (this), byte_size());
    }

    void RecursiveFree() {
        for (size_t j = 0; j < kArrayNodeLen; j++) {
            TreeNode *ptr = array_[j].load(std::memory_order_relaxed);
            ptr = TreeNode::FilterValidPtr(ptr);
            if (!ptr) {
                continue;
            }
            if (ptr->Type() == TreeNodeType::DATA_NODE) {
                ((DataNode *) ptr)->Free();
            } else if (ptr->Type() == TreeNodeType::ARRAY_NODE) {
                ((ArrayNode *) ptr)->RecursiveFree();
            } else {
                assert(1 == 0); // can't be here
            }
        }
        Free();
    }

    Atom<TreeNode *> array_[1];
};


struct concurrent_dict::ConcurrentDict::DictImpl {
    static constexpr size_t kMaxDepth = 10;
    static constexpr uintptr_t kHighestBit = 0x8000000000000000ull;
    static constexpr uintptr_t kValidPtrField = 0x0000ffffffffffffull;
public:
    static DictImpl *NewDictImpl(size_t root_size, size_t max_depth, size_t thread_cnt,
                                 Hasher hasher);

    DictImpl(size_t root_size, size_t max_depth, size_t thread_cnt, Hasher hasher);

    ~DictImpl();

    void Free();

    bool Insert(const Slice &k, const Slice &v, InsertType insert_type = InsertType::ANY);

    bool Find(const Slice &k, std::string *v);

    bool Delete(const Slice &k, std::string *v);

private:

    bool DoInsert(const Slice &k, const Slice &v, InsertType insert_type, bool del);

    size_t GetRootIdx(size_t h) const { return (h & (root_size_ - 1)); }

    size_t GetNthIdx(size_t h, size_t n) const {
        h >>= root_bits_;
        h >>= (n - 1) * ArrayNode::kArrayNodeSizeBits;
        return (h & (ArrayNode::kArrayNodeLen - 1));
    }

    static bool IsArrayNode(TreeNode *tnp) {
        return ((uintptr_t) tnp) & kHighestBit;
    }

    static TreeNode *MarkArrayNode(ArrayNode *anp) {
        return (TreeNode *) (((uintptr_t) anp) | kHighestBit);
    }

    static std::unique_ptr<ArrayNode, std::function<void(ArrayNode *)>>
    SafeArrayNodePtr() {
        return std::unique_ptr<ArrayNode, std::function<void(ArrayNode *)>>(
                ArrayNode::NewArrayNode(), [](ArrayNode *p) { p->Free(); }
        );
    }

    static std::unique_ptr<DataNode, std::function<void(DataNode *)>>
    SafeDataNodePtr(const Slice &k, const Slice &v, bool del) {
        if (del) {
            return SafeNullDataNodePtr();
        }
        return std::unique_ptr<DataNode, std::function<void(DataNode *)>>(
                DataNode::NewDataNode(k, v), [](DataNode *p) { p->Free(); }
        );
    }

    static std::unique_ptr<DataNode, std::function<void(DataNode *)>>
    SafeNullDataNodePtr() {
        return std::unique_ptr<DataNode, std::function<void(DataNode *)>>(
                nullptr, [](DataNode *p) {}
        );
    }

    using Allocator = std::allocator<uint8_t>;
    template<typename T> using Atom = std::atomic<T>;

    size_t root_size_;
    size_t root_bits_;
    size_t max_depth_;
    Hasher hasher_;
    Atom<TreeNode *> root_[1]{};
};

concurrent_dict::ConcurrentDict::DictImpl *
concurrent_dict::ConcurrentDict::DictImpl::NewDictImpl(size_t root_size, size_t max_depth,
        size_t thread_cnt, Hasher hasher) {
    root_size = next_power_of_2(root_size);
    auto ret = (DictImpl *) Allocator().allocate(sizeof(DictImpl) + sizeof(TreeNode *) * root_size);
    new(ret) DictImpl(root_size, max_depth, thread_cnt, hasher);
    return ret;
}

concurrent_dict::ConcurrentDict::DictImpl::DictImpl(size_t root_size, size_t max_depth,
        size_t thread_cnt, Hasher hasher): hasher_(hasher) {
    root_size_ = root_size;
    root_bits_ = power_of_2(root_size_);
    thread_cnt = next_power_of_2(thread_cnt);
    HazPtrInit(thread_cnt, 2);
    size_t remain = sizeof(size_t) * 8 - root_bits_;
    max_depth_ = std::min({kMaxDepth, remain / ArrayNode::kArrayNodeSizeBits, max_depth});
    for (size_t j = 0; j < root_size_; j++) {
        new(root_ + j) Atom<TreeNode *>;
        root_[j].store(nullptr, std::memory_order_release);
    }
}

concurrent_dict::ConcurrentDict::DictImpl::~DictImpl() = default;

void concurrent_dict::ConcurrentDict::DictImpl::Free() {
    for (size_t j = 0; j < root_size_; j++) {
        TreeNode *ptr = root_[j].load(std::memory_order_relaxed);
        ptr = TreeNode::FilterValidPtr(ptr);
        if (!ptr) {
            continue;
        }
        if (ptr->Type() == TreeNodeType::ARRAY_NODE) {
            ((ArrayNode *) ptr)->RecursiveFree();
        } else if (ptr->Type() == TreeNodeType::DATA_NODE) {
            ((DataNode *) ptr)->Free();
        }
    }
    Allocator().deallocate((uint8_t *) this, sizeof(*this) + sizeof(TreeNode *) * root_size_);
}

bool concurrent_dict::ConcurrentDict::DictImpl::DoInsert(const concurrent_dict::Slice &k,
                                                         const concurrent_dict::Slice &v,
                                                         concurrent_dict::InsertType insert_type, bool del) {
    size_t h = hasher_(k);
    size_t n = 0;
    size_t idx = GetRootIdx(h);
    Atom<TreeNode *> *node_ptr = &root_[idx];
    TreeNode *node = nullptr;
    HazPtrHolder holder;
    auto data_ptr = SafeNullDataNodePtr();
    bool need_pin = true;

    while (true) {
        if (need_pin) {
            node = holder.Repin(*node_ptr, IsArrayNode, TreeNode::FilterValidPtr);
        } else {
            need_pin = true;
        }

        if (!node) {
            if (insert_type == InsertType::MUST_EXIST) {
                return false;
            }

            if (!data_ptr) {
                data_ptr = SafeDataNodePtr(k, v, del);
            }

            bool res = node_ptr->compare_exchange_strong(node, (TreeNode *) data_ptr.get(),
                                                         std::memory_order_acq_rel);

            if (!res) {
                need_pin = false;
                continue;
            }
            data_ptr.release();
            return true;
        }
        assert(node);
        switch (node->Type()) {
            case TreeNodeType::DATA_NODE: {
                auto d_node = (DataNode *) node;
                if (k == d_node->Key()) {
                    if (insert_type == InsertType::DOES_NOT_EXIST) {
                        return false;
                    }

                    if (!del && d_node->UpdateValue(v)) { // In-place update
                        return true;
                    }

                    if (!data_ptr) {
                        data_ptr = SafeDataNodePtr(k, v, del);
                    }

                    bool res = node_ptr->compare_exchange_strong(node, (TreeNode *) data_ptr.get(),
                                                                 std::memory_order_acq_rel);

                    if (!res) {
                        need_pin = false;
                        continue;
                    }
                    data_ptr.release();
                    HazPtrRetire(d_node, [](void *p) { ((DataNode *) p)->Free(); });
                    return true;
                } else {
                    if (n >= max_depth_) {
                        std::cerr << "Bucket Node at max_depth is not supported yet" << std::endl;
                        exit(1);
                    } else {
                        auto new_arr_ptr = SafeArrayNodePtr();
                        size_t d_node_hash = hasher_(d_node->Key());
                        size_t d_node_idx = GetNthIdx(d_node_hash, n + 1);
                        size_t new_node_idx = GetNthIdx(h, n + 1);

                        new_arr_ptr->array_[d_node_idx].store(node, std::memory_order_release);

                        if (!data_ptr) {
                            data_ptr = SafeDataNodePtr(k, v, del);
                        }

                        if (d_node_idx != new_node_idx) {
                            new_arr_ptr->array_[new_node_idx].store(data_ptr.get(), std::memory_order_release);
                        }

                        bool res = node_ptr->compare_exchange_strong(node, MarkArrayNode(new_arr_ptr.get()),
                                                                     std::memory_order_acq_rel);

                        if (res && d_node_idx != new_node_idx) {
                            data_ptr.release();
                            new_arr_ptr.release();
                            return true;
                        }

                        if (res) {
                            n++;
                            size_t curr_idx = GetNthIdx(h, n);
                            node_ptr = &new_arr_ptr->array_[curr_idx];
                            new_arr_ptr.release();
                        } else {
                            need_pin = false;
                        }
                        continue;
                    }
                }
                break;
            }
            case TreeNodeType::ARRAY_NODE: {
                n++;
                holder.Reset();
                auto arr_node = (ArrayNode *) node;
                size_t curr_idx = GetNthIdx(h, n);
                node_ptr = &arr_node->array_[curr_idx];
                continue;
            }
            default: {
                assert(1 == 0);
            }
        }
    }

    return false;
}

inline bool concurrent_dict::ConcurrentDict::DictImpl::Insert(const concurrent_dict::Slice &k,
                                                              const concurrent_dict::Slice &v,
                                                              concurrent_dict::InsertType insert_type) {
    return DoInsert(k, v, insert_type, false);
}

bool concurrent_dict::ConcurrentDict::DictImpl::Find(const concurrent_dict::Slice &k, std::string *v) {
    size_t h = hasher_(k);

    size_t n = 0;
    size_t idx = GetRootIdx(h);
    Atom<TreeNode *> *node_ptr = &root_[idx];
    TreeNode *node = nullptr;
    HazPtrHolder holder;

    while (true) {
        node = holder.Repin(*node_ptr, IsArrayNode, TreeNode::FilterValidPtr);

        if (!node) {
            break;
        }

        switch (node->Type()) {
            case TreeNodeType::DATA_NODE: {
                auto *d_node = (DataNode *) node;
                if (k == d_node->Key()) {
                    if (v) {
                        d_node->CopyValue(*v);
                    }
                    return true;
                } else {
                    return false;
                }
            }
            case TreeNodeType::ARRAY_NODE: {
                n++;
                auto arr_node = (ArrayNode *) node;
                idx = GetNthIdx(h, n);
                node_ptr = &arr_node->array_[idx];
                break;
            }
            default: {
                assert(1 == 0); // can't be here
            }
        }
    }


    return false;
}

inline bool concurrent_dict::ConcurrentDict::DictImpl::Delete(const concurrent_dict::Slice &k, std::string *v) {
    return DoInsert(k, Slice(""), InsertType::MUST_EXIST, true);
}


concurrent_dict::ConcurrentDict::ConcurrentDict(size_t root_size, size_t max_depth, size_t thread_cnt, Hasher hasher) :
        impl_(DictImpl::NewDictImpl(root_size, max_depth, thread_cnt, hasher),
              [](DictImpl *p) { p->Free(); }) {}

concurrent_dict::ConcurrentDict::~ConcurrentDict() = default;

concurrent_dict::ConcurrentDict::ConcurrentDict(ConcurrentDict &&d) noexcept :
        impl_(std::move(d.impl_)) {}

concurrent_dict::ConcurrentDict &concurrent_dict::ConcurrentDict::operator=(
        concurrent_dict::ConcurrentDict &&d) noexcept {
    impl_ = std::move(d.impl_);
    return *this;
}

bool concurrent_dict::ConcurrentDict::Insert(const concurrent_dict::Slice &k, const concurrent_dict::Slice &v,
                                             concurrent_dict::InsertType insert_type) {
    return impl_->Insert(k, v, insert_type);
}

bool concurrent_dict::ConcurrentDict::Find(const concurrent_dict::Slice &k, std::string *v) {
    return impl_->Find(k, v);
}

bool concurrent_dict::ConcurrentDict::Delete(const concurrent_dict::Slice &k, std::string *v) {
    return impl_->Delete(k, v);
}

concurrent_dict::Hasher concurrent_dict::default_hasher = MurmurHashSlice;


