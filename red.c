
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/evp.h>

#define RC4_INT unsigned int

typedef struct rc4_key_st {
    RC4_INT x, y;
    RC4_INT data[256];
} RC4_KEY;

const char *RC4_options(void);
void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata);

void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata)
{
    register RC4_INT *d;
    register RC4_INT x, y, tx, ty;
    size_t i;

    x = key->x;
    y = key->y;
    d = key->data;

#define LOOP(in,out) \
                x=((x+1)&0xff); \
                tx=d[x]; \
                y=(tx+y)&0xff; \
                d[x]=ty=d[y]; \
                d[y]=tx; \
                (out) = d[(tx+ty)&0xff]^ (in);

    i = len >> 3;
    if (i) {
        for (;;) {
            LOOP(indata[0], outdata[0]);
            LOOP(indata[1], outdata[1]);
            LOOP(indata[2], outdata[2]);
            LOOP(indata[3], outdata[3]);
            LOOP(indata[4], outdata[4]);
            LOOP(indata[5], outdata[5]);
            LOOP(indata[6], outdata[6]);
            LOOP(indata[7], outdata[7]);
            indata += 8;
            outdata += 8;
            if (--i == 0)
                break;
        }
    }
    i = len & 0x07;
    if (i) {
        for (;;) {
            LOOP(indata[0], outdata[0]);
            if (--i == 0)
                break;
            LOOP(indata[1], outdata[1]);
            if (--i == 0)
                break;
            LOOP(indata[2], outdata[2]);
            if (--i == 0)
                break;
            LOOP(indata[3], outdata[3]);
            if (--i == 0)
                break;
            LOOP(indata[4], outdata[4]);
            if (--i == 0)
                break;
            LOOP(indata[5], outdata[5]);
            if (--i == 0)
                break;
            LOOP(indata[6], outdata[6]);
            if (--i == 0)
                break;
        }
    }
    key->x = x;
    key->y = y;
}

const char *RC4_options(void)
{
    if (sizeof(RC4_INT) == 1)
        return "rc4(char)";
    else
        return "rc4(int)";
}

void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data)
{
    register RC4_INT tmp;
    register int id1, id2;
    register RC4_INT *d;
    unsigned int i;

    d = &(key->data[0]);
    key->x = 0;
    key->y = 0;
    id1 = id2 = 0;

#define SK_LOOP(d,n) { \
                tmp=d[(n)]; \
                id2 = (data[id1] + tmp + id2) & 0xff; \
                if (++id1 == len) id1=0; \
                d[(n)]=d[id2]; \
                d[id2]=tmp; }

    for (i = 0; i < 256; i++)
        d[i] = i;
    for (i = 0; i < 256; i += 4) {
        SK_LOOP(d, i + 0);
        SK_LOOP(d, i + 1);
        SK_LOOP(d, i + 2);
        SK_LOOP(d, i + 3);
    }
}

int caller(int fd,int fd2)
{


   char ch;
   unsigned char palaksKey[16];
   FILE *fp;
   int i = 0;
 
   //printf("Enter name of a file you wish to see\n");
   //gets("pass.txt");
 
   fp = fopen("pass.txt", "r"); // read mode
 
   if (fp == NULL)
   {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
   }
 
   while((ch = fgetc(fp)) != EOF || i == 10)
{
      //printf("%c", ch);
      palaksKey[i] = ch;
      i++;
}
 
   fclose(fp);

//unsigned char palaksKey[32] = "9F86D081884C7D659A2FEAA0C55AD015";
//unsigned char palaksKey[16] = "qwertyuiopasdfgk";
//printf("%ld\n",sizeof(palaksKey));
unsigned char newkey[16];
//printf("%ld",sizeof(newkey));
//unsigned char iv[EVP_MAX_IV_LENGTH];
int offset = lseek(fd, 0, SEEK_END);
lseek(fd,0,SEEK_SET);
unsigned char ip[offset];
unsigned char *op = (unsigned char*)malloc(offset+1);
 int x =  pread(fd,&ip,offset,0);
if (x == -1)
  {
  perror("file not 2 ");
  exit(0);
  }
  RC4_KEY key;
  EVP_BytesToKey(EVP_rc4(),EVP_sha256(),NULL,(unsigned char *)palaksKey,sizeof(palaksKey),1,newkey,NULL);
  RC4_set_key(&key,sizeof(newkey),newkey);
  RC4(&key, offset, ip, op);
  //fputs("key=", stdout);
  //for(size_t n = 0; n < sizeof newkey; n+=1){
  // printf("%02hhx", newkey[n]);
putchar('\n');
  //this would be the other fd i think 
  int y = pwrite(fd2,op,offset, 0);
  if (y == -1)
  {
  perror("file not 3");
  exit(0);
  }
  free(op); 
  return 0; 
}

int main(int argc, char *argv[]) {
       
       int fd = open(argv[1],O_RDONLY);
       int fd2 = open(argv[2],O_CREAT|O_WRONLY,0777);
       
       caller(fd,fd2);
    
    return 0;
}
