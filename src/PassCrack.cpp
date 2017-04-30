/*
 * Bailey Thompson
 * Pass Crack (1.0.2)
 * 30 April 2017
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
#include "PassCrack.h"

const int PASSWORD_BUFFER = 100;
const int LETTERS = 26;
const int NUMBERS = 10;
const int CHARACTER_AMOUNT = LETTERS + LETTERS + NUMBERS;

int main() {
    char userPassword[PASSWORD_BUFFER];
    std::cout << "Input password to be cracked: ";
    std::cin.getline(userPassword, PASSWORD_BUFFER);
    char brutePassword[PASSWORD_BUFFER];
    nullEntireString(brutePassword);
    doPasswordCrack(userPassword, brutePassword);
    std::cout << "Your password has been cracked, it was: " << brutePassword << std::endl;
    return 0;
}

void nullEntireString(char brutePassword[]) {
    for (int i = 0; i < PASSWORD_BUFFER; i++) {
        brutePassword[i] = '\0';
    }
}

void doPasswordCrack(const char userPassword[], char brutePassword[]) {
    std::cout << "Starting password cracking." << std::endl;
    int length = 1;
    uint64_t i = 0;
    while (length < PASSWORD_BUFFER) {
        const int tempLength = assignPasswordBasedOnCount(brutePassword, i, length);
        if (tempLength > length) {
            std::cout << "Length is now " << tempLength << " characters." << std::endl;
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

int assignPasswordBasedOnCount(char brutePassword[], uint64_t count, int length) {
    int index = 0;
    while (count != 0 || index < length) {
        const int currentCount = (int) (count % CHARACTER_AMOUNT);
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
    std::cerr << "Error: number was not in bounds!!" << std::endl;
    return '\0';
}

bool isStringsEqual(const char userPassword[], const char brutePassword[]) {
    return strcmp(userPassword, brutePassword) == 0;
}
