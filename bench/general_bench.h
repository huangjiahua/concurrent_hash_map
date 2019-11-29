//
// Created by jiahua on 2019/9/23.
//

#pragma once

#include <iostream>
#include <random>
#include <chrono>
#include <thread>
#include <cstdint>
#include <vector>
#include <cstring>
#include <algorithm>
#include <cstddef>

#include "hash_map.h"
#include "zipf.h"

// panic function
void Panic(const char *str) {
    std::cerr << "panic: " << str << std::endl;
    exit(1);
}

// default configuration
constexpr size_t kDefaultThreadCnt = 4;
constexpr size_t kDefaultOperations = 20000000;
constexpr size_t kHashSize = 1024;
constexpr double kDefaultReadRatio = 0.8;

// configuration struct
struct Config {
    size_t thread_count = kDefaultThreadCnt;
    size_t operations = kDefaultOperations;
    size_t hash_size = kHashSize;
    double read_ratio = kDefaultReadRatio;
    bool only_tp = false;

    size_t OperationsPerThread() {
        return operations / thread_count;
    }

    void LoadConfig(int argc, const char *argv[]) {
        for (int i = 1; i < argc; i++) {
            auto arg = std::string(argv[i]);
            if (arg == "--thread") {
                if (i + 1 >= argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                thread_count = std::stoull(s);
            } else if (arg == "--operations") {
                if (i + 1 >= argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                operations = std::stoull(s);
            } else if (arg == "--hashsize") {
                if (i + 1 >= argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                hash_size = std::stoull(s);
            } else if (arg == "--read") {
                if (i + 1 > argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                read_ratio = std::stod(s);
                if (!(read_ratio >= 0.0 && read_ratio <= 1.0)) {
                    Panic("param error");
                }
            } else if (arg == "--onlytp") {
                if (i + 1 > argc) {
                    Panic("param error");
                }
                i++;
                only_tp = true;
            } else {
                Panic("param error");
            }
        }
    }

};

// random related
struct RandomGenerator {
    std::mt19937 en_;

    RandomGenerator() : en_(std::chrono::system_clock::now().time_since_epoch().count()) {}

    template<typename T = size_t>
    T Gen(T begin, T end) {
        std::uniform_int_distribution<T> dis(begin, end - 1);
        return dis(this->en_);
    }

    template<typename T = size_t>
    T GenZipf(T range, double factor) {
        zipf_distribution<T> dis(range, factor);
        return dis(this->en_);
    }

    int FlipCoin(double p) {
        std::bernoulli_distribution d(p);
        if (d(en_)) {
            return 1;
        } else {
            return 0;
        }
    }
};

// time related
struct SystemTime {
    using TimePoint =std::chrono::time_point<std::chrono::system_clock>;

    static SystemTime Now() {
        return SystemTime{std::chrono::system_clock::now()};
    }

    SystemTime() : time_point_(std::chrono::system_clock::now()) {}

    explicit SystemTime(TimePoint time_point) : time_point_(time_point) {}

    template<typename T = std::chrono::milliseconds>
    size_t DurationSince(SystemTime t) {
        auto d = this->time_point_ - t.time_point_;
        auto ret = std::chrono::duration_cast<T>(d);
        return ret.count();
    }

    TimePoint time_point_;
};

using Milliseconds = std::chrono::milliseconds;
using Seconds = std::chrono::seconds;
using Microseconds = std::chrono::microseconds;





