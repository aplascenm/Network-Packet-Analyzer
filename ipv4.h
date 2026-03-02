#ifndef IPV4_H_INCLUDED
#define IPV4_H_INCLUDED
#include <iostream>
#include <string>
#include <fstream>
#include "diccionario.h"
#include "icmpv4.h"
using namespace std;

int versionIhl(char *binaryHeader)
{
    string versionString;
    stringstream versionStream, ihlStream;
    int n;
    char *parseEndPtr;
    
    for(int i=0; i<4; i++)
    {
        versionStream<<binaryHeader[i];
    }
    
    versionString=versionStream.str();
    n=strtoull(versionString.c_str(), &parseEndPtr, 2);
    
    cout<<"Version: "<<n<<" ("<<versionString<<")"<<" -> IPV4";
    
    for(int i=4; i<8; i++)
    {
        ihlStream<<binaryHeader[i];
    }
    
    versionString=ihlStream.str();
    n=strtoull(versionString.c_str(), &parseEndPtr, 2);
    
    cout<<endl<<"IHL: "<<n<<" ("<<n*4<<")";
    
    return n*4;
}

void dscpEcn(char *binaryHeader)
{
    string bitString;
    stringstream bitStream;
    int n;
    char *parseEndPtr;
    
    for(int i=0; i<6; i++)
    {
        bitStream<<binaryHeader[i];
    }
    
    bitString=bitStream.str();
    n=strtoull(bitString.c_str(), &parseEndPtr, 2);
    
    cout<<endl<<"DSCP: "<<n;
    
    if(binaryHeader[6]=='1')
    {
        cout<<endl<<"ECN bit 1: ON";
    }else
    {
        cout<<endl<<"ECN bit 1: OFF";
    }

    if(binaryHeader[7]=='1')
    {
        cout<<endl<<"ECN bit 2: ON";
    }else
    {
        cout<<endl<<"ECN bit 2: OFF";
    }
}

void flags (char *binaryHeader)
{
    if(binaryHeader[0]=='1')
    {
        cout<<endl<<"MSB Reservado: ON";
    }else
    {
        cout<<endl<<"MSB Reservado: OFF";
    }

    if(binaryHeader[1]=='1')
    {
        cout<<endl<<"More Fragments: ON";
    }else
    {
        cout<<endl<<"More Fragments: OFF";
    }

    if(binaryHeader[2]=='1')
    {
        cout<<endl<<"Dont Fragments: ON";
    }else
    {
        cout<<endl<<"Dont Fragments: OFF";
    }
}

void fragmetsOffset(char *flagsBits, char *offsetBits)
{
    string bitString;
    stringstream flagsStream, offsetStream;
    int n, n2;
    char *endPtr;
    
    for(int i=3; i<8; i++)
    {
        flagsStream<<flagsBits[i];
    }
    
    bitString=flagsStream.str();
    n=strtoull(bitString.c_str(), &endPtr, 2);
    
    for(int i=0; i<8; i++)
    {
        offsetStream<<offsetBits[i];
    }
    
    bitString=flagsStream.str();
    n2=strtoull(bitString.c_str(), &endPtr, 2);
    
    cout<<endl<<"Fragment Offset: "<<n+n2;
}

void identificar(int protocolNumber, char *filePath, int payloadLength)
{
    if(protocolNumber==1)
    {
        icmp4(filePath,payloadLength);
    }else if(protocolNumber==6)
    {
        //tcp(c);
    }
}

void ipv4(char *filePath)
{
    int size;
    unsigned char * buffer;
    ifstream file (filePath, ios::in|ios::binary);
    
    if(!file.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        cout<<endl<<"                IPV4                 "<<endl;
        
        char *binaryByte1, *binaryByte2;
        
        ///-------MSB Y LSB----------------
        size=1;
        int headerLength;
        buffer = new unsigned char [size];
        
        file.seekg (14, ios::beg);
        file.read ((char*)buffer, size);
        
        binaryByte1=chartobin(buffer[0]);
        headerLength=versionIhl(binaryByte1);
        
        ///-------DSCP Y ECN---------------
        size=1;
        file.seekg (15, ios::beg);
        file.read ((char*)buffer, size);
        
        binaryByte1=chartobin(buffer[0]);
        dscpEcn(binaryByte1);
        
        ///-------Total Lenght-------------
        size=2;
        file.seekg (16, ios::beg);
        file.read ((char*)buffer, size);
        
        string bitString;
        long int totalLength;
        stringstream bitStream;
        char *endPtr;
        
        binaryByte1=chartobin(buffer[0]);
        bitStream<<binaryByte1;
        binaryByte1=chartobin(buffer[1]);
        bitStream<<binaryByte1;
        bitString=bitStream.str();
        totalLength=strtoull(bitString.c_str(), &endPtr, 2);
        
        cout<<endl<<"Total Lenght: "<<totalLength-headerLength;
        
        int payloadLength=totalLength-headerLength;
        
        ///------Identification------------
        size=2;
        file.seekg (18, ios::beg);
        file.read ((char*)buffer, size);
        
        stringstream identificationStream;
        binaryByte1=chartobin(buffer[0]);
        identificationStream<<binaryByte1;
        binaryByte1=chartobin(buffer[1]);
        identificationStream<<binaryByte1;
        
        bitString=identificationStream.str();
        totalLength=strtoull(bitString.c_str(), &endPtr, 2);
        
        cout<<endl<<"Identification: "<<totalLength;
        
        ///---------FLAGS-------------------
        size=1;
        file.seekg (20, ios::beg);
        file.read ((char*)buffer, size);
        
        binaryByte1=chartobin(buffer[0]);
        flags(binaryByte1);
        
        ///---------Fragment Offset---------
        size=2;
        file.seekg (20, ios::beg);
        file.read ((char*)buffer, size);
        
        binaryByte1=chartobin(buffer[0]);
        binaryByte2=chartobin(buffer[1]);
        fragmetsOffset(binaryByte1, binaryByte2);
        
        ///----------Time To Life-----------
        size=1;
        file.seekg (22, ios::beg);
        file.read ((char*)buffer, size);
        
        cout<<endl<<"Time to life: "<<(int)buffer[0];
        
        ///---------Protocol----------------
        int protocolNumber;
        size=1;
        file.seekg (23, ios::beg);
        file.read ((char*)buffer, size);
        
        stringstream protocolStream;
        protocolStream<<(int)buffer[0];
        bitString=protocolStream.str();
        
        protocolNumber=verificarIPT(bitString);
        
        ///--------Header Checksum----------
        size=2;
        file.seekg (24, ios::beg);
        file.read ((char*)buffer, size);
        
        stringstream checksumStream;
        checksumStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[0];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[1];
       
        bitString="0x"+checksumStream.str();
        cout<<endl<<"Header Checksum: "<<bitString;
        
        ///---------Direccion Origen-----------
        size=4;
        file.seekg (26, ios::beg);
        file.read ((char*)buffer, size);
        
        cout<<endl<<"Sender IP: ";
        
        for(int j=0; j<4; j++)
        {
            printf("%d", (int)buffer[j]);
            if(j<3)
            {
                cout<<".";
            }
        }

        ///---------Direccion Destino----------
        size=4;
        file.seekg (30, ios::beg);
        file.read ((char*)buffer, size);
        
        cout<<endl<<"Tarjet IP: ";
        
        for(int j=0; j<4; j++)
        {
            printf("%d", (int)buffer[j]);
            if(j<3)
            {
                cout<<".";
            }
        }

        ///-----------Data----------------------
        identificar(protocolNumber, filePath,payloadLength);
    }
    
    delete[] buffer;
    file.close();
}

#endif // IPV4_H_INCLUDED
