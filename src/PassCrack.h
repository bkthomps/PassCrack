/*
 * Provides function definitions for password cracking using brute force.
 */

#ifndef PASS_CRACK_H
#define PASS_CRACK_H

int main(void);

bool isGetUserPasswordSuccessful(char userPassword[], int size);

void removeBackspace(char userPassword[]);

void nullEntireString(char brutePassword[]);

void doPasswordCrack(const char userPassword[], char brutePassword[]);

int assignPasswordBasedOnCount(char brutePassword[], int count, int length);

char convertNumberToCharacter(int number);

bool isStringsEqual(const char userPassword[], char brutePassword[]);

#endif /* PASS_CRACK_H */
