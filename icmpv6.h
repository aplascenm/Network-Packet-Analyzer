#ifndef ICMPV6_H_INCLUDED
#define ICMPV6_H_INCLUDED
#include <iostream>
#include <fstream>
#include "diccionario.h"
using namespace std;

void icmp6 (char *fileName)
{
    int tam = 2;
    unsigned char * buffer;
    ifstream inputFile (fileName, ios::in|ios::binary);
    
    if(!inputFile.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        cout<<endl<<endl<<"                ICMPV6                 "<<endl;
        string typeCodeString;
        int ident;
        ///----------------TYPE, CODE-----------------------

        buffer = new unsigned char [tam];
        inputFile.seekg (54, ios::beg);
        inputFile.read ((char*)buffer, tam);
        
        stringstream typeCodeStringStream;
        typeCodeStringStream<<(int)buffer[0];

        if((int)buffer[0]<10)
        {
            typeCodeStringStream<<"-"<<(int)buffer[1];
        }else{
            typeCodeStringStream<<"-0";
        }
        
        typeCodeString=typeCodeStringStream.str();
        ident=verificarIcmp6(typeCodeString);
        ///---------------Checksum----------------------------
       
        inputFile.seekg (56, ios::beg);
        inputFile.read ((char*)buffer, tam);
        stringstream checksumStream;
        checksumStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[0];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[1];
        typeCodeString="0x"+checksumStream.str();
        cout<<endl<<"Header Checksum: "<<typeCodeString;
    }
}

#endif // ICMPV6_H_INCLUDED
