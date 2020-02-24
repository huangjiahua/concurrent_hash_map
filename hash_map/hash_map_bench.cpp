//
// Created by jiahua on 2019/10/24.
//
#ifdef USE_DICT
#include "hash_map/dict_test_wrapper.h"
#else
#include "hash_map/concurrent_hash_map.h"
#endif
#include "general_bench.h"
#include <vector>
#include <fstream>

constexpr static size_t kDefaultInitSize = 65536;
constexpr static size_t kDefaultKeyRange = 10000000000ull;

struct HMBConfig {
    size_t thread_count = 4;
    size_t operations = kDefaultOperations;
    size_t initial_size = kDefaultInitSize;
    size_t key_range = 1000000000ull;
    double read_ratio = 1.0;
    size_t max_depth = 20;
    double zipf_factor = 0.99;
    bool only_tp = false;
    bool uniform = false;
    bool inplace = false;

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
            } else if (arg == "--keyrange") {
                if (i + 1 >= argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                key_range = std::stoull(s);
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
            } else if (arg == "--zipf") {
                if (i + 1 > argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                zipf_factor = std::stod(s);
            } else if (arg == "--rootsize") {
                if (i + 1 > argc) {
                    Panic("param error");
                }
                i++;
                auto s = std::string(argv[i]);
                initial_size = std::stoull(s);
            } else if (arg == "--uniform") {
                if (i + 1 > argc) {
                    Panic("param error");
                }
                i++;
                uniform = true;
            } else if (arg == "--inplace") {
                if (i + 1 > argc) {
                    Panic("param error");
                }
                i++;
                inplace = true;
            } else {
                Panic("param error");
            }
        }
    }
};

using namespace std;
#ifdef USE_DICT
using Map = DictTestWrapper;
#else
using Map = ConcurrentHashMap<uint64_t, uint64_t, std::hash<uint64_t>, std::equal_to<>>;
#endif

constexpr static size_t kROUND = 10;

int main(int argc, const char *argv[]) {
    HMBConfig config;
    config.LoadConfig(argc, argv);
    RandomGenerator rng;
    size_t per_thread_task = config.operations / config.thread_count;

#ifdef USE_DICT
    concurrent_dict::ConcurrentDict dict(config.initial_size, config.max_depth, config.thread_count);
    DictTestWrapper map(&dict);
#else
    ConcurrentHashMap<uint64_t, uint64_t, std::hash<uint64_t>, std::equal_to<>> map(config.initial_size,
                                                                                    config.max_depth,
                                                                                    config.thread_count);
#endif

    for (size_t i = 0; i < config.operations; i++) {
        if (config.uniform) {
            map.Insert(rng.Gen<uint64_t>(0, config.key_range), 0);
        } else {
            map.Insert(rng.GenZipf<uint64_t>(config.key_range, config.zipf_factor), 0);
        }
    }

    vector<uint64_t> keys(config.operations + 1000);
    for (auto &key : keys) {
        if (config.uniform) {
            key = rng.Gen<uint64_t>(0, config.key_range);
        } else {
            key = rng.GenZipf<uint64_t>(config.key_range, config.zipf_factor);
        }
    }
    vector<int> coins(config.operations + 1000);
    for (auto &coin: coins) coin = rng.FlipCoin(config.read_ratio);
    vector<thread> threads(config.thread_count);
    vector<size_t> times(config.thread_count, 0);

    auto worker = [per_thread_task, config](size_t idx, Map &map, uint64_t *keys, int *coins, size_t &time) {
        auto t = SystemTime::Now();
        uint64_t value = 0;
        for (size_t i = 0; i < kROUND; i++) {
            for (size_t j = 0; j < per_thread_task; j++) {
                if (coins[j]) {
                    map.Find(keys[j], value);
                } else {
                    if (config.inplace) {
#ifndef DISABLE_INPLACE_UPDATE
                        map.InplaceUpdate(keys[j], keys[j] + idx);
#else
                        map.Insert(keys[j], keys[j] + idx);
#endif
                    } else {
                        map.Insert(keys[j], keys[j] + idx);
                    }
                }
            }
        }
        time = SystemTime::Now().DurationSince<std::chrono::microseconds>(t);
    };

    for (size_t i = 0; i < threads.size(); i++) {
        threads[i] = thread(worker, i, std::ref(map), keys.data() + i * per_thread_task,
                            coins.data() + i * per_thread_task, std::ref(times[i]));
    }

    for (auto &t : threads) t.join();

    size_t average_time = std::accumulate(times.begin(), times.end(), 0ull) / times.size();
    double tp = (double) config.operations * (double) kROUND / (double) average_time;

    cout << tp << endl;

    return 0;
}