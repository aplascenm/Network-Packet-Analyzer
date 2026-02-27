#include <iostream>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include "diccionario.h"
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "icmpv4.h"
#include "ipv6.h"
#include "pcap.h"
using namespace std;

int main()
{
    char userInput[30];
    int fileNameLength;
    bool hasBinExtension=false;
    cout<<endl<<"Ingrese Nombre de Paquete (Insert name File): ";
    cin>>userInput;
    cout<<endl;
    ///Agregar el .bin
    //Adding .bin
    string fileNameStr(userInput);
    fileNameLength=fileNameStr.size();
    
    if(fileNameStr[fileNameLength-4]=='.')
    {
        if(fileNameStr[fileNameLength-3]=='b')
        {
            if(fileNameStr[fileNameLength-2]=='i')
            {
                hasBinExtension=true;
            }
        }
    }
    
    if(!hasBinExtension)
    {
        fileNameStr.append(".bin");
    }
    
    strncpy(userInput, fileNameStr.c_str(), sizeof(userInput));
    userInput[sizeof(userInput) - 1] = 0;
    ifstream inputFile (userInput);
    
    if(!inputFile.is_open())
    {
        cout<<endl<<"Error.";
    }else
    {
        ///------------ETHERNET-----------------------------
        ifstream inputFile (userInput);
        int fileStartPosition,fileEndPosition,payloadSize;
        string etherType;
        fileStartPosition= inputFile.tellg();
        inputFile.seekg (0, ios::end);
        fileEndPosition= inputFile.tellg();
        payloadSize=fileEndPosition-fileStartPosition-18;
        inputFile.seekg (0);
        
        cout<<"Tamano Paquete: "<<fileEndPosition<<endl;
        ///direcciones
        //adresses
        direcciones(userInput);
        ///tipo
        //type
        etherType=tipo(userInput);
        ///Carga util
        //Useful load
        cout<<endl<<"Hay "<<payloadSize<<" Bytes de carga util.";
        ///crc
        crc(userInput, payloadSize);
        cout<<endl;
        
        for(int i=0; i<100; i++)
        {
            if(dEthertype[i]==etherType)
            {
                if(dEthertype[i+2]=="ARP")
                {
                    ///------------ARP----------------------------------
                    arp(userInput);
                }
                if(dEthertype[i+2]=="IPV4")
                {
                    ///------------IPV4----------------------------------
                    ipv4(userInput);
                }
                if(dEthertype[i+2]=="IPV6")
                {
                    ///------------IPV6----------------------------------
                    ipv6(userInput);
                }
            }
        }

    }

    inputFile.close();

    return 0;
}
