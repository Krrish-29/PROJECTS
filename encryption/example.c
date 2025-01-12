#include"arcfour.h"
#define F fflush(stdout)
void printbin(int8 *input,const int16 size){
    int16 i;
    int8 *p;
    assert(size>0);
    for(i=0,p=input;i<size;i++,p++){
        printf("%.02x",*p);
        fflush(stdout);
        if(!(i%2)){
            printf(" ");
            fflush(stdout); 
        }
    }
    printf("\n");
}
export Arcfour *rc4init(int8*key,int16 keysize){
    int16 x;;
    int8 temp1=0,temp2=0;
    int32 n;
    Arcfour* ptr=(Arcfour*)calloc(1,sizeof(Arcfour));
    for(x=0;x<256;x++){
        ptr->s[x]=0;
    }
    ptr->i=ptr->j=ptr->k=0;
    for(ptr->i=0;ptr->i<256;ptr->i++){
        ptr->s[ptr->i]=ptr->i;
    }
    for(ptr->i=0;ptr->i<256;ptr->i++){
        temp1=ptr->i%keysize;
        temp2=ptr->j+ptr->s[ptr->i]+key[temp1];
        ptr->j=temp2%256;
        temp1=ptr->s[ptr->i];
        temp2=ptr->s[ptr->j];
        ptr->s[ptr->i]=temp2;
        ptr->s[ptr->j]=temp1;
    }
    ptr->i=ptr->j=0;
    rc4whitewash(n,ptr);
    return ptr;
}
int8 rc4byte(Arcfour *ptr){
    int16 temp1,temp2;
    ptr->i=(ptr->i+1)%256;
    ptr->j=(ptr->j+ptr->s[ptr->i])%256;
    temp1=ptr->s[ptr->i];
    temp2=ptr->s[ptr->j];
    ptr->s[ptr->i]=temp2;
    ptr->s[ptr->j]=temp1;
    temp1=(ptr->s[ptr->i]+ptr->s[ptr->j])%256;
    ptr->k= ptr->s[temp1];
    return ptr->k;
}
export int8 *rc4encrypt(Arcfour*ptr,int8*cleartext,int16 size){
    int8 *ciphertext;
    int16 x;
    ciphertext=(int8*)calloc(1,size+1);
    for(x=0;x<size;x++){
        ciphertext[x]=cleartext[x]^rc4byte(ptr);
    }
    return ciphertext;
}
int main(){
    Arcfour*rc4;
    int16 sizeKey, sizeText;
    char *key,*from;
    int8 *encrypted,*decrypted;
    key="tomatoes";//8 bits to 2048 bits
    sizeKey=strlen(key);
    from="Shall I compare thee to a summer's day?";
    sizeText=strlen(from);
    printf("Initializing encryption...");
    rc4=rc4init((int8*)key,sizeKey);
    printf("done\n");
    printf("'%s\n->",from);
    encrypted=rc4encrypt(rc4,from,sizeText);
    printbin(encrypted,sizeText);
    rc4uninit(rc4);
    printf("Initializing decryption...");
    rc4=rc4init((int8*)key,sizeKey);
    printf("done\n");
    decrypted=rc4encrypt(rc4,encrypted,sizeText);
    printf("   ->'%s\n",decrypted);
}