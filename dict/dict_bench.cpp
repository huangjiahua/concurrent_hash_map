#include "concurrent_dict.h"
#include <string>
#include <iostream>

using namespace concurrent_dict;
using namespace std;

int main() {
    ConcurrentDict dict(65536, 20, 8);
    const int round = 1000;
    for (int i = 0; i < round; i++) {
        string dat = to_string(i);
        dict.Insert(Slice(dat), Slice(dat));
        dict.Insert(Slice(dat), Slice("0"));
    }
    for (int i = 0; i < round; i++) {
        string key = to_string(i);
        string val;
        auto res = dict.Find(Slice(key), &val);
        assert(res);
        assert(val == "0");
    }
    return 0;
}