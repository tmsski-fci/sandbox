#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>

int main() {
    SHA512_CTX ctx;
    unsigned char buffer[512];

    char *str = "this is a test";
    int len = strlen(str);

    strcpy(buffer,str);

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, buffer, len);
    SHA512_Final(buffer, &ctx);

    fwrite(&buffer,64,1,stdout);

    return 0;
}