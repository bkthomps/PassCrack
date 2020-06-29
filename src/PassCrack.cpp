/*
 * Bailey Thompson
 * Pass Crack
 * Version 1.1.2
 *
 * Cracks a password using brute force. Length of the password which is being computed starts at one, and every
 * character combination of that length is computed. If no combination matches the password in which the user entered,
 * the length is increased and every possible character combination of that length is subsequently computed. This goes
 * on until the password is cracked, checking to determine if the computed password matches the password the user
 * entered after every new combination.
 * Disclaimer: Please do not use this with malicious intent.
 */

#include <iostream>
#include <cstring>
#include <cmath>
#include <vector>
#include <thread>
#include "PassCrack.h"

const int PASSWORD_BUFFER = 100;
const int LETTERS = 26;
const int NUMBERS = 10;
const int CHARACTER_AMOUNT = LETTERS + LETTERS + NUMBERS;

int main() {
    char userPassword[PASSWORD_BUFFER];
    std::cout << "Input password to be cracked: ";
    std::cin.getline(userPassword, PASSWORD_BUFFER);
    doPasswordCrack(userPassword);
    std::cerr << "Error: should never return from main!!" << std::endl;
}

void doPasswordCrack(const char userPassword[]) {
    unsigned int concurrentThreadsSupported = std::thread::hardware_concurrency();
    if (concurrentThreadsSupported == 0) {
        concurrentThreadsSupported = 4;
    }
    std::cout << "Your system supports " << concurrentThreadsSupported << " concurrent threads." << std::endl;
    std::cout << "Starting password cracking." << std::endl;
    startThreads(userPassword, concurrentThreadsSupported);
    std::cerr << "Error: startThreads should never return!!" << std::endl;
}

void startThreads(const char userPassword[], unsigned int concurrentThreadsSupported) {
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < concurrentThreadsSupported; i++) {
        threads.emplace_back(std::thread(thread, userPassword, i, concurrentThreadsSupported));
    }
    for (auto &thread : threads) {
        thread.join();
    }
}

void thread(const char userPassword[], int threadId, int amountOfThreads) {
    char brutePassword[PASSWORD_BUFFER];
    nullEntireString(brutePassword);
    int length = 1;
    uint64_t count = minimumCount(threadId, amountOfThreads, length) - 1;
    uint64_t maxCount = maximumCount(threadId, amountOfThreads, length);
    while (length < PASSWORD_BUFFER) {
        assignPasswordBasedOnCount(brutePassword, count, length);
        if (count >= maxCount) {
            length++;
            count = minimumCount(threadId, amountOfThreads, length) - 1;
            maxCount = maximumCount(threadId, amountOfThreads, length);
            assignPasswordBasedOnCount(brutePassword, count, length);
        }
        if (isStringsEqual(userPassword, brutePassword)) {
            std::cout << "Thread " << threadId + 1 << " - Password was cracked, it was: " << brutePassword << std::endl;
            exit(0);
        }
        count++;
    }
}

void nullEntireString(char brutePassword[]) {
    for (int i = 0; i < PASSWORD_BUFFER; i++) {
        brutePassword[i] = '\0';
    }
}

uint64_t minimumCount(int threadId, int amountOfThreads, int length) {
    if (threadId == 0) {
        return 1;
    }
    return maximumCount(threadId - 1, amountOfThreads, length) + 1;
}

uint64_t maximumCount(int threadId, int amountOfThreads, int length) {
    const int indexCount = highestCount(length) * (threadId + 1) / amountOfThreads;
    return (uint64_t) ((threadId == amountOfThreads - 1) ? indexCount : indexCount + 1);
}

int highestCount(int length) {
    return (int) pow(CHARACTER_AMOUNT, length);
}

void assignPasswordBasedOnCount(char brutePassword[], uint64_t count, int length) {
    int index = 0;
    while (count != 0 || index < length) {
        const int currentCount = (int) (count % CHARACTER_AMOUNT);
        count /= CHARACTER_AMOUNT;
        brutePassword[index] = convertNumberToCharacter(currentCount);
        index++;
    }
}

char convertNumberToCharacter(int number) {
    if (number < LETTERS) {
        return (char) (number + 'a');
    }
    number -= LETTERS;
    if (number < LETTERS) {
        return (char) (number + 'A');
    }
    number -= LETTERS;
    if (number < NUMBERS) {
        return (char) (number + '0');
    }
    std::cerr << "Error: number was not in bounds!!" << std::endl;
    return '\0';
}

bool isStringsEqual(const char userPassword[], const char brutePassword[]) {
    return strcmp(userPassword, brutePassword) == 0;
}
