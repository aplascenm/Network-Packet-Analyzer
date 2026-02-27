#ifndef IPV6_H_INCLUDED
#define IPV6_H_INCLUDED
#include <iostream>
#include <fstream>
#include <string>
#include "diccionario.h"
#include "icmpv6.h"


using namespace std;

void versionipv6(char *binaryHeader)
{
    string versionBits;
    stringstream versionBitsStream;
    int versionNumber;
    char *parseEndPtr;
    
    for(int i = 0; i<4; i++)
    {
        versionBitsStream<<binaryHeader[i];
    }
    
    versionBits = versionBitsStream.str();
    versionNumber = strtoull(versionBits.c_str(), &parseEndPtr, 2);
    cout<<"Version: "<<versionNumber<<" ("<<versionBits<<")"<<" -> IPV6";
}

void trafficClass(char *firstByteBinary, char *secondByteBinary)
{
    string highBits,lowBits;
    stringstream highBitsStream, lowBitsStream;
    int highValue, lowValue;
    char *parseEndPtr;

    for(int i = 4; i<8; i++)
    {
        highBitsStream<<firstByteBinary[i];
    }

    highBits = highBitsStream.str();
    highValue = strtoull(highBits.c_str(), &parseEndPtr, 2);

    for(int i = 0; i<4; i++)
    {
        lowBitsStream<<secondByteBinary[i];
    }

    lowBits = lowBitsStream.str();
    lowValue = strtoull(highBits.c_str(), &parseEndPtr, 2);
    printf("\nTraffic Class: 0x%02x%02x",highValue, lowValue);
}

void flowLabel(char *firstByteBinary, char *secondByteBinary, char *thirdByteBinary)
{
    string bitSegment,combinedBits;
    stringstream firstSegmentStream, secondSegmentStream, thirdSegmentStream,combinedStream;
    unsigned long int flowLabelDecimal;
    char *parseEndPtr;
    for(int i = 4; i<8; i++)
    {
        firstSegmentStream<<firstByteBinary[i];
    }
    bitSegment = firstSegmentStream.str();

    combinedStream<<bitSegment;
    for(int i = 0; i<8; i++)
    {
        secondSegmentStream<<secondByteBinary[i];
    }
    bitSegment = secondSegmentStream.str();
    combinedStream<<bitSegment;

    for(int i = 0; i<8; i++)
    {
        thirdSegmentStream<<thirdByteBinary[i];
    }
    bitSegment = thirdSegmentStream.str();
    combinedStream<<bitSegment;
    combinedBits = combinedStream.str();
    flowLabelDecimal = strtoull(combinedBits.c_str(), &parseEndPtr, 2);
    cout<<endl<<"Flow Label: "<<flowLabelDecimal;
}

void ipv6(char *fileName)
{
    int tam;
    unsigned char * ch;
    ifstream inputFile (fileName, ios::in|ios::binary);
    
    if(!inputFile.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        cout<<endl<<"                IPV6                 "<<endl;
        char *binaryByte1, *binaryByte2, *binaryByte3;
        ///-------------version---------------------
        tam = 1;
        ch = new unsigned char [tam];
        inputFile.seekg (14, ios::beg);
        inputFile.read ((char*)ch, tam);
        binaryByte1 = chartobin(ch[0]);
        versionipv6(binaryByte1);
        ///----------Traffic class-------------------
        tam = 2;
        inputFile.seekg (14, ios::beg);
        inputFile.read ((char*)ch, tam);
        binaryByte1 = chartobin(ch[0]);
        binaryByte2 = chartobin(ch[1]);
        trafficClass(binaryByte1, binaryByte2);
        ///----------Flow Label-----------------------
        tam = 3;
        inputFile.seekg (15, ios::beg);
        inputFile.read ((char*)ch, tam);
        binaryByte1 = chartobin(ch[0]);
        binaryByte2 = chartobin(ch[1]);
        binaryByte3 = chartobin(ch[2]);
        flowLabel(binaryByte1, binaryByte2, binaryByte3);
        ///----------Payload Lenght-------------------
        tam = 2;
        inputFile.seekg (18, ios::beg);
        inputFile.read ((char*)ch, tam);
        char *parseEndPtr;
        long int n;
        string payloadBits;
        stringstream payloadBitsStream,z;
        binaryByte1 = chartobin(ch[0]);
        payloadBitsStream<<binaryByte1;
        binaryByte1 = chartobin(ch[1]);
        payloadBitsStream<<binaryByte1;
        payloadBits = payloadBitsStream.str();
        n = strtoull(payloadBits.c_str(), &parseEndPtr, 2);
        cout<<endl<<"Payload Lenght: "<<n;
        ///----------Next Header-------------------
        int num;
        tam = 1;
        inputFile.seekg (20, ios::beg);
        inputFile.read ((char*)ch, tam);
        stringstream sss;
        sss<<(int)ch[0];
        payloadBits = sss.str();
        num = verificarIPT6(payloadBits);
        ///----------Hop Limit---------------------
        tam = 1;
        inputFile.seekg (21, ios::beg);
        inputFile.read ((char*)ch, tam);
        cout<<endl<<"Hop Limit: "<<(int)ch[0];
        ///----------Source address----------------
        tam = 16;
        inputFile.seekg (22, ios::beg);
        inputFile.read ((char*)ch, tam);
        cout<<endl<<"Source Address: ";
        int cont = 0;
        for(int j = 0; j<16; j++)
        {
            printf("%02x", (int)ch[j]);
            cont++;
            if(j<15)
            {
                if(cont == 2)
                {
                cont = 0;
                cout<<":";
                }
            }
        }

        ///----------Destination address-----------
        tam = 16;
        inputFile.seekg (38, ios::beg);
        inputFile.read ((char*)ch, tam);
        cout<<endl<<"Destination Address: ";
        cont = 0;
        for(int j = 0; j<16; j++)
        {
            printf("%02x", (int)ch[j]);
            cont++;
            if(j<15)
            {
                if(cont == 2)
                {
                cont = 0;
                cout<<":";
                }
            }
        }

        ///-----------------DATA--------------------
        if(num == 58)
        {
            icmp6(fileName);
        }
    }

    delete[] ch;
    inputFile.close();
}

#endif // IPV6_H_INCLUDED
