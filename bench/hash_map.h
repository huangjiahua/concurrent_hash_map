//
// Created by jiahua on 2019/9/23.
//

#pragma once

#include <vector>
#include <mutex>
#include <atomic>
#include <memory>

#ifdef BOOST_ARC
#include <boost/smart_ptr/atomic_shared_ptr.hpp>
#endif
#ifdef MRSW_PTR
#include "mrsw_ptr/mrsw_ptr.h"
#endif
#ifdef HAZ_PTR

#include "haz_ptr/haz_ptr.h"

#endif

#ifdef HAZ_PTR

struct Wrapper : public hazptr_obj_base<Wrapper> {
    uint64_t data;

    Wrapper(uint64_t i) : data(i) {}

    uint64_t &Get() { return data; }

    uint64_t &Set(const uint64_t &i) {
        data = i;
        return data;
    }
};

#endif
#ifdef MY_HAZ_PTR
#include "my_haz_ptr/haz_ptr.h"
#endif

// hash map related
template<typename T, typename V = T>
class HashMap {
public:
    std::vector<V> values_;
    std::vector<std::unique_ptr<V>> ptrs_;
    std::vector<std::mutex> locks_;
    std::vector<std::atomic<const T *>> atomic_ptrs_;
#ifdef BOOST_ARC
    using Arc = boost::atomic_shared_ptr<T>;
    using Rc = boost::shared_ptr<T>;
    std::vector<Arc> arcs;
#endif
#ifdef MRSW_PTR
    using Mrsw = MrswPtr<T>;
    std::vector<Mrsw> mps;
#endif
#ifdef HAZ_PTR
    std::vector<std::atomic<Wrapper*>> haz_ptrs_;
#endif
#ifdef MY_HAZ_PTR
    std::vector<std::atomic<const T *>> haz_atomics_;
#endif

    explicit HashMap(size_t size);

    bool Get(size_t key, T &value);

    bool Put(size_t key, const T &value, bool overwrite = true);

    bool Put(size_t key, T &&value, bool overwrite = true);

    bool Delete(size_t key);

    bool Check() const;

    size_t Size() const;
};

//template<typename T>
//HashMap<T>::HashMap(size_t size) {
//
//}
//
//template<typename T>
//bool HashMap<T>::Get(size_t key, T &value) {
//    return false;
//}
//
//template<typename T>
//bool HashMap<T>::Put(size_t key, const T &value, bool overwrite) {
//    return false;
//}
//
//template<typename T>
//bool HashMap<T>::Put(size_t key, T &&value, bool overwrite) {
//    return false;
//}
//
//template<typename T>
//bool HashMap<T>::Delete(size_t key) {
//    return false;
//}
//
//template<typename T>
//size_t HashMap<T>::Size() const {
//    return 0;
//}
