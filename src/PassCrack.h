/*
 * Provides function definitions for password cracking using brute force.
 */

#ifndef PASS_CRACK_H
#define PASS_CRACK_H

int main();

void doPasswordCrack(const char userPassword[]);

void startThreads(const char userPassword[], unsigned int concurrentThreadsSupported);

void thread(const char userPassword[], int threadId, int amountOfThreads);

void nullEntireString(char brutePassword[]);

uint64_t minimumCount(int threadId, int amountOfThreads, int length);

uint64_t maximumCount(int threadId, int amountOfThreads, int length);

int highestCount(int length);

void assignPasswordBasedOnCount(char brutePassword[], uint64_t count, int length);

char convertNumberToCharacter(int number);

bool isStringsEqual(const char userPassword[], const char brutePassword[]);

#endif /* PASS_CRACK_H */
