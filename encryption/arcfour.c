#include"arcfour.h"
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