#include <string>

#include "dict/concurrent_dict.h"

class DictTestWrapper {
    using Dict = concurrent_dict::ConcurrentDict;
    using Slice = concurrent_dict::Slice;
public:
    explicit DictTestWrapper(Dict *dict) : key_buf_(sizeof(uint64_t), ' '),
                                           val_buf_(sizeof(uint64_t), ' '),
                                           dict_(dict) {}

    bool Insert(const uint64_t &key, const uint64_t &value) {
        char *key_p = (char *) (&key);
        char *val_p = (char *) (&value);
        Slice key_slice(key_p, sizeof(uint64_t));
        Slice val_slice(val_p, sizeof(uint64_t));
        return dict_->Insert(key_slice, val_slice);
    }

    bool InplaceUpdate(const uint64_t &key, const uint64_t &value) {
        char *key_p = (char *) (&key);
        char *val_p = (char *) (&value);
        Slice key_slice(key_p, sizeof(uint64_t));
        Slice val_slice(val_p, sizeof(uint64_t));
        return dict_->Insert(key_slice, val_slice);
    }

    bool Find(const uint64_t &key, uint64_t &value) {
        char *key_p = (char *) (&key);
        Slice key_slice(key_p, sizeof(uint64_t));
        bool res = dict_->Find(key_slice, &val_buf_);
        if (res) {
            value = *((uint64_t *) val_buf_.data());
        }
        return res;
    }

private:
    std::string key_buf_;
    std::string val_buf_;
    Dict *dict_;
};