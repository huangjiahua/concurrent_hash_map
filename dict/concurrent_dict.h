#pragma once

#include <cstddef>

#include <memory>
#include <functional>

#include "slice.h"

namespace concurrent_dict {

enum class InsertType {
    ANY,
    DOES_NOT_EXIST,
    MUST_EXIST
};

class ConcurrentDict {
public:
    ConcurrentDict(size_t root_size, size_t max_depth, size_t thread_cnt);

    ~ConcurrentDict();

    ConcurrentDict(const ConcurrentDict &) = delete;

    ConcurrentDict &operator=(const ConcurrentDict &) = delete;

    ConcurrentDict(ConcurrentDict &&d) noexcept;

    ConcurrentDict &operator=(ConcurrentDict &&d) noexcept;

    bool Insert(const Slice &k, const Slice &v, InsertType insert_type = InsertType::ANY);

    bool Find(const Slice &k, std::string *v);

    bool Delete(const Slice &k, std::string *v);

private:
    struct DictImpl;
    std::unique_ptr<DictImpl, std::function<void(DictImpl*)>> impl_;
};

} // namespace concurrent_dict