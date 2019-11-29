//
// Created by jiahua on 2019/11/16.
//

#pragma once

#include <cstdint>
#include <memory>

class PreAllocator {
public:
    static PreAllocator *Create(size_t size) {
        PreAllocator *pa = (PreAllocator *) std::allocator<uint8_t>().allocate(
                sizeof(PreAllocator) + size * sizeof(uint8_t));
        new(pa) PreAllocator;
        pa->size_ = size;
        return pa;
    }

    void Destroy() {
        auto size = size_;
        std::allocator<uint8_t>().deallocate((uint8_t *) this, sizeof(*this) + size * sizeof(uint8_t));
    }

private:
    size_t size_{0};
    uint8_t mem_[0];
};
