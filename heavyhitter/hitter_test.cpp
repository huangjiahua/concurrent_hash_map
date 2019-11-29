//
// Created by jiahua on 2019/11/5.
//

#include "heavyhitter/GeneralLazySS.h"

#include <iostream>

using std::cout;
using std::endl;

int main() {
    GeneralLazySS<uint64_t> ss(0.0001);
    for (size_t i = 0; i < 899; i++) {
        ss.put(1);
    }

    for (size_t i = 0; i < 999; i++) {
        ss.put(2);
    }

    cout << ss.size() << endl;
    cout << ss.find(1)->getCount() << endl;
    cout << ss.output(true)[1].getCount() << endl;

}

