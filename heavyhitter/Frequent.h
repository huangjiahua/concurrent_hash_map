//
// Created by Michael on 2019-10-15.
//

#ifndef HASHCOMP_FREQUENT_H
#define HASHCOMP_FREQUENT_H

#include <map>
#include "Structure.h"

class Frequent {
private:
    Node *head;
    Node *tail;
    std::multimap<int, Node *> fasttbl;
    int bsize;
public:
    Frequent(int size) : head(new Node(-1, -1)), tail(new Node(-1, -1)), bsize(size) {
        head->setNext(tail);
        tail->setPrev(head);
    }

    ~Frequent() {
        while (head->getNext() != nullptr) {
            head = head->getNext();
            delete head->getPrev();
        }
        delete head;
    }

#ifndef NDEBUG

    Node *header() { return head; }

#endif

    int size() { return fasttbl.size(); }

    void add(int v) {
        auto cur = fasttbl.find(v);
        if (cur != fasttbl.end()) {
            Node *n = dynamic_cast<Node *>(cur->second);
            n->increase();
            Node *p = n->getPrev();
            while (p->getPrev() != nullptr && p->getPrev()->getFreq() <= n->getFreq()) { p = p->getPrev(); }
            n->getNext()->setPrev(n->getPrev());
            n->getPrev()->setNext(n->getNext());
            n->setNext(p->getNext());
            p->getNext()->setPrev(n);
            p->setNext(n);
            n->setPrev(p);
        } else {
            if (fasttbl.size() < bsize) {
                Node *add = new Node(v, 1);
                tail->getPrev()->setNext(add);
                add->setPrev(tail->getPrev());
                add->setNext(tail);
                tail->setPrev(add);
                fasttbl.insert(std::make_pair(v, add));
            } else {
                Node *iter = tail->getPrev();
                bool added = false;
                if (iter->getFreq() == 0) added = true;
                if (added) {
                    while (iter->getFreq() == 0) iter = iter->getPrev();
                    iter = iter->getNext();
                    fasttbl.erase(iter->getIndex());
                    iter->setFreq(1);
                    iter->setIndex(v);
                    fasttbl.insert(std::make_pair(v, iter));
                } else {
                    while (iter->getPrev() != nullptr) {
                        int index = iter->getIndex();
                        fasttbl.erase(index);
                        iter->setFreq(iter->getFreq() - 1);
                        fasttbl.insert(std::make_pair(index, iter));
                        iter = iter->getPrev();
                    }
                }
            }
        }
    }
};

#endif //HASHCOMP_FREQUENT_H
