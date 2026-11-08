#include <stdio.h>
#include <string.h>
int main(void) {
    const char *secret = "donotleak-this-token-1234";
    printf("hello dossier! token=%s\n", secret);
    if (strlen(secret) > 5) return 0;
    return 1;
}
