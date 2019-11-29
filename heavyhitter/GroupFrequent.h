//
// Created by iclab on 10/29/19.
//

#ifndef HASHCOMP_GROUPFREQUENT_H
#define HASHCOMP_GROUPFREQUENT_H

#include <cmath>
#include <cstdint>
#include <random>
//#include "prng.h"

class ItemList;

class Group {
private:
    int diff;
    ItemList *items;
    Group *prevg, *nextg;
public:
    void setDiff(int d) { diff = d; }

    void chgDiff(int d) { diff += d; }

    int getDiff() { return diff; }

    void setItems(ItemList *its) { items = its; }

    ItemList *getItems() { return items; }

    void setPrevg(Group *g) { prevg = g; }

    Group *getPrevg() { return prevg; }

    void setNextg(Group *g) { nextg = g; }

    Group *getNextg() { return nextg; }
};

class ItemList {
private:
    int item;
    Group *parents;
    ItemList *previ, *nexti;
    ItemList *next, *prev;
public:
    void setItem(int value) { item = value; }

    int getItem() { return item; }

    void setGroup(Group *g) { parents = g; }

    Group *getGroup() { return parents; }

    void setPrevi(ItemList *node) { previ = node; }

    ItemList *getPrevi() { return previ; }

    void setNexti(ItemList *node) { nexti = node; }

    ItemList *getNexti() { return nexti; }

    void setPrev(ItemList *node) { prev = node; }

    ItemList *getPrev() { return prev; }

    void setNext(ItemList *node) { next = node; }

    ItemList *getNext() { return next; }
};

constexpr int MOD = 2147483647;

constexpr int HL = 31;

class GroupFrequent {
private:
    ItemList **hashtable;
    Group *groups;
    int k;
    int tblsz;
    int64_t a, b;

    inline long hash31(int64_t a, int64_t b, int64_t x) {
        int64_t result;
        long lresult;
        result = (a * x) + b;
        result = ((result >> HL) + result) & MOD;
        lresult = (long) result;

        return (lresult);
    }

private:
    ItemList *GetNewCounter() {
        ItemList *newi;
        int j;
        newi = groups->getItems();
        groups->setItems(groups->getItems()->getNext());
        newi->getNext()->setPrev(newi->getPrev());
        newi->getPrev()->setNext(newi->getNext());
        j = hash31(a, b, newi->getItem()) % tblsz;
        if (hashtable[j] == newi) hashtable[j] = newi->getNexti();
        if (newi->getNexti() != nullptr) newi->getNexti()->setPrevi(newi->getPrevi());
        if (newi->getPrevi() != nullptr) newi->getPrevi()->setNexti(newi->getNexti());
        return newi;
    }

    void InsertIntoHashtable(ItemList *newi, int i, int newitem) {
        newi->setNexti(hashtable[i]);
        newi->setItem(newitem);
        newi->setPrevi(nullptr);
        if (hashtable[i] != nullptr) {
            hashtable[i]->setPrevi(newi);
        }
        hashtable[i] = newi;
    }

    void InsertIntoFirstGroup(ItemList *newi) {
        Group *firstg = groups->getNextg();
        newi->setGroup(firstg);
        newi->setNext(firstg->getItems());
        newi->setPrev(firstg->getItems()->getPrev());
        newi->getPrev()->setNext(newi);
        firstg->getItems()->setPrev(newi);
    }

    void CreateFirstGroup(ItemList *newi) {
        Group *newg, *firstg;
        firstg = groups->getNextg();
        newg = new Group();
        newg->setDiff(1);
        newg->setItems(newi);
        newi->setNext(newi);
        newi->setPrev(newi);
        newi->setGroup(newg);
        newg->setNextg(firstg);
        newg->setPrevg(groups);
        groups->setNextg(newg);
        if (firstg != nullptr) {
            firstg->setPrevg(newg);
            firstg->chgDiff(-1);
        }
    }

    void PutInNewGroup(ItemList *newi, Group *tmpg) {
        Group *oldg;
        oldg = newi->getGroup();
        newi->setGroup(tmpg);
        if (newi->getNext() != newi) {
            newi->getNext()->setPrev(newi->getPrev());
            newi->getPrev()->setNext(newi->getNext());
            oldg->setItems(oldg->getItems()->getNext());
        } else {
            if (oldg->getDiff() != 0) {
                if (oldg->getNextg() != nullptr) {
                    oldg->getNextg()->chgDiff(oldg->getDiff());
                    oldg->getNextg()->setPrevg(oldg->getPrevg());
                }
                oldg->getPrevg()->setNextg(oldg->getNextg());
                delete oldg;
            }
        }
        newi->setNext(tmpg->getItems());
        newi->setPrev(tmpg->getItems()->getPrev());
        newi->getPrev()->setNext(newi);
        newi->getNext()->setPrev(newi);
    }

    void AddNewGroupAfter(ItemList *newi, Group *oldg) {
        Group *newg;
        newi->getNext()->setPrev(newi->getPrev());
        newi->getPrev()->setNext(newi->getNext());
        oldg->setItems(newi->getNext());
        newg = new Group();
        newg->setDiff(1);
        newg->setItems(newi);
        newg->setPrevg(oldg);
        newg->setNextg(oldg->getNextg());
        oldg->setNextg(newg);
        if (newg->getNextg() != nullptr) {
            newg->getNextg()->chgDiff(-1);
            newg->getNextg()->setPrevg(newg);
        }
        newi->setGroup(newg);
        newi->setNext(newi);
        newi->setPrev(newi);
    }

    void AddNewGroupBefore(ItemList *newi, Group *oldg) {
        Group *newg;
        newi->getNext()->setPrev(newi->getPrev());
        newi->getPrev()->setNext(newi->getNext());
        oldg->setItems(newi->getNext());
        newg = new Group();
        newg->setDiff(oldg->getDiff() - 1);
        oldg->setDiff(1);
        newg->setItems(newi);
        newg->setNextg(oldg);
        newg->setPrevg(oldg->getPrevg());
        oldg->setPrevg(newg);
        if (newg->getPrevg() != nullptr) {
            newg->getPrevg()->setNextg(newg);
        }
        newi->setGroup(newg);
        newi->setNext(newi);
        newi->setPrev(newi);
    }

    void DeleteFirstGroup() {
        Group *tmpg;
        groups->getNextg()->getItems()->getPrev()->setNext(groups->getItems()->getNext());
        groups->getItems()->getNext()->setPrev(groups->getNextg()->getItems()->getPrev());
        groups->getNextg()->getItems()->setPrev(groups->getItems());
        groups->getItems()->setNext(groups->getNextg()->getItems());

        tmpg = groups->getNextg();
        groups->getNextg()->setDiff(0);
        groups->setNextg(groups->getNextg()->getNextg());
        if (groups->getNextg() != nullptr) {
            groups->getNextg()->setPrevg(groups);
        }
        tmpg->setNextg(nullptr);
        tmpg->setPrevg(nullptr);
    }

    void IncrementCounter(ItemList *newi) {
        Group *oldg;
        oldg = newi->getGroup();
        if (oldg->getNextg() != nullptr && oldg->getNextg()->getDiff() == 1) {
            PutInNewGroup(newi, oldg->getNextg());
        } else {
            if (newi->getNext() == newi) {
                newi->getGroup()->chgDiff(1);
                if (newi->getGroup()->getNextg() != nullptr)
                    newi->getGroup()->getNextg()->chgDiff(-1);
            } else {
                AddNewGroupAfter(newi, oldg);
            }
        }
    }

    void SubtractCounter(ItemList *newi) {
        Group *oldg;
        oldg = newi->getGroup();
        if (oldg->getNextg() != nullptr && oldg->getNextg()->getDiff() == 1) {
            PutInNewGroup(newi, oldg->getNextg());
        } else {
            if (newi->getNext() == newi) {
                newi->getGroup()->chgDiff(-1);
                if (newi->getGroup()->getNextg() != nullptr)
                    newi->getGroup()->getNextg()->chgDiff(1);
            } else {
                AddNewGroupAfter(newi, oldg);
            }
        }
    }

    void DecrementCounters() {
        if (groups->getNextg() != nullptr && groups->getNextg()->getDiff() > 0) {
            groups->getNextg()->chgDiff(-1);
            if (groups->getNextg()->getDiff() == 0) {
                DeleteFirstGroup();
            }
        }
    }

    void FirstGroup(ItemList *newi) {
        if (groups->getNextg() != nullptr && groups->getNextg()->getDiff() == 1) {
            InsertIntoFirstGroup(newi);
        } else {
            CreateFirstGroup(newi);
        }
    }

    void RecycleCounter(ItemList *il) {
        if (il->getNext() == il) {
            DecrementCounters();
        } else {
            if (groups->getItems() == il) {
                groups->setItems(groups->getItems()->getNext());
            }
            il->getNext()->setPrev(il->getPrev());
            il->getPrev()->setNext(il->getNext());
            FirstGroup(il);
        }
    }

public:
    GroupFrequent(double phi) : k((int) ceil(1.0 / phi)) {
        if (k < 1) k = 1;
        /*prng_type *prng = prng_Init(45445, 2);
        prng_int(prng);
        prng_int(prng);
        prng_int(prng);
        prng_int(prng);
        this->a = (int64_t) (prng_int(prng) % MOD);
        this->b = (int64_t) (prng_int(prng) % MOD);
        prng_Destroy(prng);*/
        srand(time(NULL));
        this->a = (int64_t) (rand() % MOD);
        this->b = (int64_t) (rand() % MOD);

        tblsz = 2 * k;
        hashtable = new ItemList *[2 * k + 2];

        for (int i = 0; i < 2 * k; i++) hashtable[i] = nullptr;

        groups = new Group();
        groups->setDiff(0);
        groups->setNextg(nullptr);
        groups->setPrevg(nullptr);
        ItemList *prevItem = new ItemList();
        groups->setItems(prevItem);
        prevItem->setNexti(nullptr);
        prevItem->setPrevi(nullptr);
        prevItem->setGroup(groups);
        prevItem->setNext(prevItem);
        prevItem->setPrev(prevItem);
        prevItem->setItem(0);

        for (int i = 0; i <= k; i++) {
            ItemList *initItem = new ItemList();
            initItem->setItem(0);
            initItem->setGroup(groups);
            initItem->setNexti(nullptr);
            initItem->setPrevi(nullptr);
            initItem->setNext(prevItem);
            initItem->setPrev(prevItem->getPrev());
            prevItem->getPrev()->setNext(initItem);
            prevItem->setPrev(initItem);
        }
    }

    ~GroupFrequent() {
        Group *curg = groups, *nextg;
        do {
            nextg = curg->getNextg();
            /*ItemList *curi = curg->getItems(), *nexti;
            do {
                nexti = curi->getNext();
                delete curi;
            } while ((curi = nexti) != nullptr);*/
            delete curg;
        } while ((curg = nextg) != nullptr);
        delete[] hashtable;
    }

    int size() {
        return 2 * tblsz * sizeof(ItemList *) + (k + 1) * sizeof(ItemList) + k * sizeof(Group);
    }

    int volume() {
        return k;
    }

    int range() {
        return tblsz;
    }

    void put(int item) {
        int i;
        ItemList *il;
        int diff;
        if (item > 0) diff = 1;
        else {
            item = -item;
            diff = -1;
        }

        i = hash31(a, b, item) % tblsz;
        il = hashtable[i];
        while (il != nullptr) {
            if ((il->getItem()) == item) break;
            il = il->getNexti();
        }
        if (il == nullptr) {
            if (diff == 1) {
                if (groups->getItems()->getNext() != groups->getItems()) {
                    il = GetNewCounter();
                    InsertIntoHashtable(il, i, item);
                    FirstGroup(il);
                } else DecrementCounters();
            }
        } else if (diff == 1) {
            if (il->getGroup()->getDiff() == 0) RecycleCounter(il);
            else IncrementCounter(il);
        } else if (il->getGroup()->getDiff() != 0)
            SubtractCounter(il);
    }
};

#endif //HASHCOMP_GROUPFREQUENT_H
