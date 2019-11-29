//
// Created by Michael on 2019-10-15.
//

#ifndef HASHCOMP_SPACESAVING_H
#define HASHCOMP_SPACESAVING_H

#include <iostream>
#include <map>
#include <vector>
#include <queue>
#include <iterator>
//#include <bits/stdc++.h>

template<class IntType>
class RAWSS {
    std::multimap<IntType, int> raw;
    int v;
    int f;
    int m;

public:
    void put(IntType v) {
        auto iter = raw.find(v);
        if (iter == raw.end()) {
            raw.insert(std::make_pair(v, 1));
        } else {
            iter->second++;
        }
    }

    std::multimap<int, IntType, std::greater<int>> export_stats() {
        std::multimap<int, IntType, std::greater<int>> stat;
        for (auto &iter : raw) {
            stat.insert(std::make_pair(iter.second, iter.first));
        }
        return stat;
    }

    RAWSS(int capacity) : m(capacity) {

    }
};


template<class IntType>
class SS {
    class Counter {
    public:
        IntType v;
        int f;
        int e;

        Counter() {

        }

        Counter(int V) : v(V), f(1), e(0) {

        }
    };

    class Entry {
    public:
        std::multimap<IntType, Counter *> refs;

        //std::queue<int, Counter&> ages;
        Entry() {

        }

        void add(Counter *c) {
            refs.insert(std::make_pair(c->v, c));
        }

        void del(IntType v) {
            refs.erase(v);
        }

        int size() {
            return refs.size();
        }
    };

    bool validate() {
        int ic = 0;
        for (auto &entry : index) {
            ic += entry.second.size();
        }
        return ic == m;
    }

public:
    std::multimap<int, Entry> index;
    std::multimap<IntType, Counter *> counters;
    int m = 0;
    int t = 0;
    int n = 0;

    void put(IntType v) {
        auto iter = counters.find(v);
        t++;
        //        std::cout << t << counters.size() << std::endl;
        //        if (t >= 93 || !validate()) {
        //            int hhh = 9;
        //        }
        if (iter == counters.end()) {
            if (counters.size() == m) {
                // Obtain the minimal granularity.
                auto l1 = index.begin();
                // Without aging, but comes true in our real dataset due the increasing id.
                //                Entry list = l1->second;
                Counter *counter = l1->second.refs.begin()->second;
                IntType oldv = counter->v;
                l1->second.del(oldv);
                // Add to the next granularity.
                //                Entry list = l1->second;
                //auto oldl1 = l1;
                int empty = 0xffffffff;
                if (l1->second.size() == 0) {
                    //index.erase(oldl1);
                    empty = counter->f;
                }
                counter->v = v;
                counter->e = counter->f;
                counter->f++;
                //                if (t >= 14) {
                //                    int hello  = 9;
                //                }
                l1++;
                //                list = l1->second;
                //                int ff = l1->first;
                //                list = l1->second;
                counters.insert(std::make_pair(v, counter));
                if (l1 == index.end() || (l1)->first != counter->f) {
                    Entry entry;
                    entry.add(counter);
                    index.insert(std::make_pair(counter->f, entry));
                    //entry.add(counter);
                } else {
                    l1->second.add(counter);
                }
                if (empty != 0xffffffff) {
                    index.erase(empty);
                }
                counters.erase(oldv);
                //                list = l1->second;
            } else {
                if (n++ >= m) {
                    std::cout << "Too many new counter: " << n << std::endl;
                }
                Counter *counter = new Counter(v);
                counters.insert(std::make_pair(v, counter));
                auto l1 = index.find(1);
                if (l1 == index.end()) {
                    Entry entry;
                    entry.add(counter);
                    index.insert(std::make_pair(1, entry));
                } else {
                    l1->second.add(counter);
                    //                    auto l1 = index.find(1);
                }
            }
        } else {
            int freq = iter->second->f;
            auto it = index.find(freq);
            //            Entry entry = it->second;
            //            if (it == index.end()){
            //                std::cout << "In counters but not in index" << std::endl;
            //                exit(-1);
            //            }
            // Remove from the current granularity.
            it->second.del(iter->second->v);
            int empty = 0xffffffff;
            if (it->second.size() == 0) {
                empty = it->first;
            }
            // Add to the next granularity.
            it++;
            if (it == index.end() || it->first != freq + 1) {
                Entry entry;
                entry.add(iter->second);
                index.insert(std::make_pair(freq + 1, entry));
            } else {
                it->second.add(iter->second);
            }
            iter->second->f++;
            if (empty != 0xffffffff) {
                index.erase(empty);
            }
            //counters.erase(iter);
        }
    }

    std::multimap<int, IntType, std::greater<int>> export_stats() {
        std::multimap<int, IntType, std::greater<int>> stat;
        for (auto &iter : counters) {
            stat.insert(std::make_pair(iter.second->f, iter.first));
        }
        return stat;
    }

    int getCounterNumber() {
        return this->counters.size();
    }

    SS(int capacity) : m(capacity) {

    }
};

template<class IntType>
class ASS {
    class Counter {
    public:
        IntType v;
        int f;
        int e1;
        int e2;

        Counter() {

        }

        Counter(int V) : v(V), f(1), e1(0), e2(0) {

        }
    };

    class Entry {
    public:
        std::multimap<IntType, Counter *> refs;

        //std::queue<int, Counter&> ages;
        Entry() {

        }

        void add(Counter *c) {
            refs.insert(std::make_pair(c->v, c));
        }

        void del(IntType v) {
            refs.erase(v);
        }

        int size() {
            return refs.size();
        }
    };

public:
    std::multimap<int, Entry> index;
    std::multimap<IntType, Counter> counters;
    int m;
    int t;

    void put(IntType v) {

    }


    std::multimap<int, IntType, std::greater<int>> export_stats() {

    }

    int getCounterNumber() {
        return this->counters.size();
    }

    ASS(int capacity) : m(capacity) {

    }
};

#endif //HASHCOMP_SPACESAVING_H
