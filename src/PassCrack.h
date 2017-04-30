/*
 * Provides function definitions for password cracking using brute force.
 */

#ifndef PASS_CRACK_H
#define PASS_CRACK_H

int main();

void nullEntireString(char brutePassword[]);

void doPasswordCrack(const char userPassword[], char brutePassword[]);

int assignPasswordBasedOnCount(char brutePassword[], uint64_t count, int length);

char convertNumberToCharacter(int number);

bool isStringsEqual(const char userPassword[], const char brutePassword[]);

#endif /* PASS_CRACK_H */
