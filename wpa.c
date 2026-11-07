#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX_LEN 256

/* Convert char to 0-25 range (A-Z / a-z). Returns -1 if not a letter */
int char_to_num(char c) {
    if (isupper(c)) return c - 'A';
    if (islower(c)) return c - 'a';
    return -1;
}

/* Convert 0-25 back to letter, preserving original case */
char num_to_char(int num, char original) {
    num = (num % 26 + 26) % 26;          /* handle negative */
    if (isupper(original)) return 'A' + num;
    return 'a' + num;
}

/* Generate a repeating key of the same length as the plaintext */
void generate_keystream(const char *key, size_t text_len, char *keystream) {
    size_t key_len = strlen(key);
    size_t j = 0;

    for (size_t i = 0; i < text_len; i++) {
        if (isalpha(key[j % key_len])) {
            keystream[i] = tolower(key[j % key_len]);
            j++;
        } else {
            /* skip non-letters in key */
            j++;
            i--;
        }
    }
    keystream[text_len] = '\0';
}

/* Encrypt plaintext with Vigenère */
void vigenere_encrypt(const char *plaintext, const char *key, char *ciphertext) {
    size_t len = strlen(plaintext);
    char keystream[MAX_LEN];

    generate_keystream(key, len, keystream);

    for (size_t i = 0; i < len; i++) {
        int p = char_to_num(plaintext[i]);
        if (p == -1) {
            ciphertext[i] = plaintext[i];   /* keep non-letters */
            continue;
        }
        int k = char_to_num(keystream[i]);
        int c = (p + k) % 26;
        ciphertext[i] = num_to_char(c, plaintext[i]);
    }
    ciphertext[len] = '\0';
}

/* Decrypt ciphertext with Vigenère */
void vigenere_decrypt(const char *ciphertext, const char *key, char *plaintext) {
    size_t len = strlen(ciphertext);
    char keystream[MAX_LEN];

    generate_keystream(key, len, keystream);

    for (size_t i = 0; i < len; i++) {
        int c = char_to_num(ciphertext[i]);
        if (c == -1) {
            plaintext[i] = ciphertext[i];
            continue;
        }
        int k = char_to_num(keystream[i]);
        int p = (c - k + 26) % 26;          /* +26 to avoid negative */
        plaintext[i] = num_to_char(p, ciphertext[i]);
    }
    plaintext[len] = '\0';
}

int main(void) {
    char wifi_password[MAX_LEN];
    char secret_key[MAX_LEN];
    char encrypted[MAX_LEN];
    char decrypted[MAX_LEN];

    printf("=== Simple WiFi Credential Protector (Vigenère) ===\n");
    printf("(Educational only – NOT real security!)\n\n");

    printf("Enter WiFi password / SSID: ");
    if (fgets(wifi_password, sizeof(wifi_password), stdin) == NULL) {
        fprintf(stderr, "Input error\n");
        return 1;
    }
    wifi_password[strcspn(wifi_password, "\n")] = '\0';   /* remove newline */

    printf("Enter secret key: ");
    if (fgets(secret_key, sizeof(secret_key), stdin) == NULL) {
        fprintf(stderr, "Input error\n");
        return 1;
    }
    secret_key[strcspn(secret_key, "\n")] = '\0';

    if (strlen(secret_key) == 0) {
        fprintf(stderr, "Key cannot be empty\n");
        return 1;
    }

    /* Encrypt */
    vigenere_encrypt(wifi_password, secret_key, encrypted);
    printf("\nEncrypted  : %s\n", encrypted);

    /* Decrypt */
    vigenere_decrypt(encrypted, secret_key, decrypted);
    printf("Decrypted  : %s\n", decrypted);

    /* Quick check */
    if (strcmp(wifi_password, decrypted) == 0) {
        printf("\n✓ Round-trip successful\n");
    } else {
        printf("\n✗ Round-trip failed\n");
    }

    return 0;
}
