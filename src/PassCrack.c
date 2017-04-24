/*
 * Bailey Thompson
 * Pass Crack (1.0.0)
 * 23 April 2017
 *
 * Cracks a password using brute force. Length of the password which is being computed starts at one, and every
 * character combination of that length is computed. If no combination matches the password in which the user entered,
 * the length is increased and every possible character combination of that length is subsequently computed. This goes
 * on until the password is cracked, checking to determine if the computed password matches the password the user
 * entered after every new combination.
 * Disclaimer: Please do not use this with malicious intent.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "PassCrack.h"

#define PASSWORD_BUFFER 100
#define LETTERS 26
#define NUMBERS 10
#define CHARACTER_AMOUNT (LETTERS + LETTERS + NUMBERS)

int main(void) {
    char userPassword[PASSWORD_BUFFER];
    const bool isPassWordGetSuccess = isGetUserPasswordSuccessful(userPassword, sizeof userPassword);
    if (!isPassWordGetSuccess) {
        fprintf(stderr, "Error: user password input failed!\n");
        return -1;
    }
    removeBackspace(userPassword);
    char brutePassword[PASSWORD_BUFFER];
    nullEntireString(brutePassword);
    doPasswordCrack(userPassword, brutePassword);
    printf("Your password has been cracked, it was: %s\n", brutePassword);
    return 0;
}

bool isGetUserPasswordSuccessful(char userPassword[], int size) {
    return fgets(userPassword, size, stdin) != NULL;
}

void removeBackspace(char userPassword[]) {
    const int BACKSPACE = 10;
    for (int i = 0; i < PASSWORD_BUFFER; i++) {
        if (userPassword[i] == BACKSPACE) {
            userPassword[i] = '\0';
        }
    }
}

void nullEntireString(char brutePassword[]) {
    for (int i = 0; i < PASSWORD_BUFFER; i++) {
        brutePassword[i] = '\0';
    }
}

void doPasswordCrack(const char userPassword[], char brutePassword[]) {
    printf("Starting password cracking.\n");
    int length = 1;
    long i = 0;
    while (length < PASSWORD_BUFFER) {
        const int tempLength = assignPasswordBasedOnCount(brutePassword, i, length);
        if (tempLength > length) {
            printf("Length is now %i characters.\n", tempLength);
            length = tempLength;
            i = 0;
            assignPasswordBasedOnCount(brutePassword, i, length);
        }
        if (isStringsEqual(userPassword, brutePassword)) {
            return;
        }
        i++;
    }
}

int assignPasswordBasedOnCount(char brutePassword[], int count, int length) {
    int index = 0;
    while (count != 0 || index < length) {
        const int currentCount = count % CHARACTER_AMOUNT;
        count /= CHARACTER_AMOUNT;
        brutePassword[index] = convertNumberToCharacter(currentCount);
        index++;
    }
    return index;
}

char convertNumberToCharacter(int number) {
    const int ASCII_LOWER_CASE_A = 97;
    const int ASCII_UPPER_CASE_A = 65;
    const int ASCII_ZERO = 48;
    if (number < LETTERS) {
        return (char) (ASCII_LOWER_CASE_A + number);
    }
    number -= LETTERS;
    if (number < LETTERS) {
        return (char) (ASCII_UPPER_CASE_A + number);
    }
    number -= LETTERS;
    if (number < NUMBERS) {
        return (char) (ASCII_ZERO + number);
    }
    fprintf(stderr, "Error: number was not in bounds.\n");
    return '\0';
}

bool isStringsEqual(const char userPassword[], char brutePassword[]) {
    return strcmp(userPassword, brutePassword) == 0;
}
