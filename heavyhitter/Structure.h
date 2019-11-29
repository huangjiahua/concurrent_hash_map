//
// Created by Michael on 10/28/2019.
//

#ifndef HASHCOMP_STRUCTURE_H
#define HASHCOMP_STRUCTURE_H

class Node {
private:
    int index;
    int frequency;
    int e1;
    Node *prev;
    Node *next;

public:
    Node(int idx, int freq) : index(idx), frequency(freq), e1(0), prev(nullptr), next(nullptr) {}

    void setIndex(int idx) { index = idx; }

    int getIndex() { return index; }

    void setFreq(int freq) { frequency = freq; }

    int getFreq() { return frequency; }

    int increase(int n = 1) { frequency += n; }

    void setE1(int e) { e1 = e; }

    int getE1() { return e1; }

    void setPrev(Node *n) { prev = n; }

    Node *getPrev() { return prev; }

    void setNext(Node *n) { next = n; }

    Node *getNext() { return next; }
};

#endif //HASHCOMP_STRUCTURE_H
