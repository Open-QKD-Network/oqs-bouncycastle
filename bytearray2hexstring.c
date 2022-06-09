#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

//0123456789abcdef
uint8_t char2int(char c) {
    if (c >= 'a' && c <= 'f') {
        return (c - 'a') + 10;
    } else if (c >= 'A' && c <= 'F') {
        return (c - 'A') + 10;
    } else {
        return (c - '0');
    }
}

//stackoverflow.com/questions/6357031/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-in-c/ 
char* bytearray2hexstring(uint8_t* buf, int size) {
    char *ptr = malloc(size * 2 + 1);
    char *ret = ptr;
    int i = 0;

    memset(ptr, 0, size*2 + 1);
    for (i = 0; i < size; i++)
        ptr += sprintf(ptr, "%02X", buf[i]); 
    return ret;
}

uint8_t* hexstring2bytearray(char* hexstring, int* size) {
    int len = strlen(hexstring)/2;
    uint8_t *ret = malloc(len);
    memset(ret, 0, len);
    int i = 0;
    for (i = 0; i < len; i++) {
        uint8_t c0 = char2int(hexstring[i*2]);
        uint8_t c1 = char2int(hexstring[i*2 + 1]);
        uint8_t r = (c0 << 4) + c1;
        *(ret + i) = r;
        printf("#%d %c %c %d %d %d\n", i, hexstring[i*2], hexstring[i*2 +1], c0, c1, r);
    }
    *size = len;
    return ret;
}

int writebytearraytofile(uint8_t* buf, int size, char* filename) {
    FILE *fp;
    char* hexstring;

    hexstring = bytearray2hexstring(buf, size);
    fp = fopen(filename, "w+");
    if (fp) {
        fputs(hexstring, fp);
        fclose(fp);
        free(hexstring);
        return 0;
    } else {
        return -1;
    }
}

uint8_t* readbytearrayfromfile(char* filename, int* size) {
    FILE *fp;
    long length;
    char *hexstring = 0;

    if (!filename)
        return NULL;
    fp = fopen(filename, "rb");
    if (!fp) {
        printf("Fails to read file:%s\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("Size of the file:%d\n", length);
    hexstring = malloc(length + 1);
    memset(hexstring, 0, length + 1);
    if (hexstring)
    {
        fread(hexstring, 1, length, fp);
    }
    fclose(fp);
 
    printf("Hexstring:%s\n", hexstring);
    return hexstring2bytearray(hexstring, size);
}

#define SIZE 256
int main() {
    uint8_t buf[SIZE];
    uint8_t *buf2;
    int i, size;
    for ( i  = 0; i < SIZE; i++) {
        buf[i] = i;
    }
    /*char* hexstring = bytearray2hexstring(buf, 255);
    printf("%s\n", hexstring);
    buf2 = hexstring2bytearray(hexstring, &size);
    for (i = 0; i < size; i++) {
        printf("%d ", *(buf2 + i));
    }
    free(buf2);
    printf("\n");*/
    writebytearraytofile(buf, SIZE, "array.txt");
    size = 0;
    buf2 = readbytearrayfromfile("array.txt", &size);
    for (i = 0; i < size; i++) {
        printf("%d ", *(buf2 + i));
    }
    return 1;
}
