#include "concurrent_dict.h"
#include <string>
#include <iostream>

using namespace concurrent_dict;
using namespace std;

int main() {
    ConcurrentDict dict(65536, 20, 8);
    for (int i = 0; i < 100; i++) {
        string dat = to_string(i);
        dict.Insert(Slice(dat), Slice(dat));
        dict.Insert(Slice(dat), Slice("0"));
    }
    for (int i = 0; i < 100; i++) {
        string key = to_string(i);
        string val;
        dict.Find(Slice(key), &val);
        cout << val << endl;
    }
    return 0;
}