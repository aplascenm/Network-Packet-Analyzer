#ifndef ICMP_H_INCLUDED
#define ICMP_H_INCLUDED
#include <iostream>
#include <fstream>
#include "diccionario.h"

using namespace std;

void icmp4 (char *fileName,int ipPayloadLength)
{
    int icmpCategory;
    int bytesToRead;
    unsigned char * buffer;

    ifstream inputFile (fileName, ios::in|ios::binary);
    
    if(!inputFile.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        cout<<endl<<endl<<"                ICMPV4                 "<<endl;
        
        string typeCodeString;
        
        ///----------------TYPE, CODE-----------------------
        bytesToRead=2;
        buffer = new unsigned char [bytesToRead];
        
        inputFile.seekg (34, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        char *binaryByte, *parseEndPtr;
        stringstream typeCodeStringStream;
        
        typeCodeStringStream<<(int)buffer[0];
        
        if((int)buffer[0]==3||(int)buffer[0]==5||(int)buffer[0]==11)
        {
            typeCodeStringStream<<"-"<<(int)buffer[1];
        }else{
            typeCodeStringStream<<"-0";
        }
        
        typeCodeString=typeCodeStringStream.str();
        icmpCategory=verificarIcmp4(typeCodeString);
        
        ///---------------Checksum----------------------------
        bytesToRead=2;
        inputFile.seekg (36, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);

        stringstream checksumStream;

        checksumStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[0];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[1];
        
        typeCodeString="0x"+checksumStream.str();
        cout<<endl<<"Header Checksum: "<<typeCodeString;
        
        if(icmpCategory==0||icmpCategory==8)
        {
            ///--------------Identificador-------------------------
            bytesToRead=2;
            inputFile.seekg (38, ios::beg);
            inputFile.read ((char*)buffer, bytesToRead);
            
            long int n;
            stringstream identifierStream;
            
            binaryByte=chartobin(buffer[0]);
            identifierStream<<binaryByte;
            
            binaryByte=chartobin(buffer[1]);
            identifierStream<<binaryByte;
            
            typeCodeString=identifierStream.str();
            n=strtoull(typeCodeString.c_str(), &parseEndPtr, 2);
           
            cout<<endl<<"Identificador: "<<n;
            
            ///--------------Secuencia------------------------------
            bytesToRead=2;
            inputFile.seekg (40, ios::beg);
            inputFile.read ((char*)buffer, bytesToRead);
            
            stringstream sequenceStream;
            
            binaryByte=chartobin(buffer[0]);
            sequenceStream<<binaryByte;
            
            binaryByte=chartobin(buffer[1]);
            sequenceStream<<binaryByte;
            
            typeCodeString=sequenceStream.str();
            n=strtoull(typeCodeString.c_str(), &parseEndPtr, 2);
            
            cout<<endl<<"Numero de Secuencia: "<<n;
            
            ///------------------Payload-----------------------------
            cout<<endl<<"Payload Lenght: "<<ipPayloadLength-8;
        }else if(icmpCategory==3)
        {
            cout<<endl<<"Payload Lenght: "<<ipPayloadLength-4;
        }else if(icmpCategory==5)
        {
            ///--------------Gateway---------------------------------
            bytesToRead=4;
            inputFile.seekg (38, ios::beg);
            inputFile.read ((char*)buffer, bytesToRead);
            
            cout<<endl<<"Gateway: ";
            
            for(int j=0; j<4; j++)
            {
                printf("%d", (int)buffer[j]);
                if(j<3)
                {
                    cout<<".";
                }
            }
            
            ///------------Payload------------------------------------
            cout<<endl<<"Payload Lenght: "<<ipPayloadLength-8;
        }else if(icmpCategory==1)
        {
            cout<<endl<<"Payload Lenght: "<<ipPayloadLength-4;
        }

    }
}

#endif // ICMP_H_INCLUDED
