#ifndef ARP_H_INCLUDED
#define ARP_H_INCLUDED
#include <iostream>
#include <fstream>
using namespace std;

void arp (char *fileName)
{
    int bytesToRead;
    unsigned char * buffer;
    
    ifstream inputFile (fileName, ios::in|ios::binary);
    
    if(!inputFile.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        cout<<endl<<"                ARP                 "<<endl;
        
        bytesToRead=2;
        buffer = new unsigned char [bytesToRead];
        
        ///-------Hardware type------------------------
        inputFile.seekg (14, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        char *binaryByte, *parseEndPtr;
        long int n;
        string hardwareTypeString;
        stringstream hardwareTypeStream,decimalStream;
        
        binaryByte=chartobin(buffer[0]);
        hardwareTypeStream<<binaryByte;
        
        binaryByte=chartobin(buffer[1]);
        hardwareTypeStream<<binaryByte;
        
        hardwareTypeString=hardwareTypeStream.str();
        n=strtoull(hardwareTypeString.c_str(), &parseEndPtr, 2);
        
        decimalStream<<n;
        hardwareTypeString=decimalStream.str();
        
        verificarHT(hardwareTypeString);
        
        ///-------Protocol Type------------------------
        bytesToRead=2;
        inputFile.seekg (16, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        stringstream protocolTypeStream;
        
        protocolTypeStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[0];
        protocolTypeStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[1];
        
        hardwareTypeString="0x"+protocolTypeStream.str();
        
        cout<<endl<<"Protocol Type: ";
        verificardE(hardwareTypeString);
        
        ///-------Hardware Size------------------------
        bytesToRead=1;
        inputFile.seekg (18, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        cout<<endl<<"Hardware Size: "<<(int)buffer[0];
        
        ///-------Protocol Size------------------------
        bytesToRead=1;
        inputFile.seekg (19, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        cout<<endl<<"Protocol Size: "<<(int)buffer[0];
        
        ///-------OPCODE/request/reply-----------------
        bytesToRead=1;
        cout<<endl<<"OPCODE: ";
        
        inputFile.seekg (21, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        if((int)buffer[0]==1)
        {
            cout<<(int)buffer[0]<<" -> Request";
        }else
        {
            cout<<(int)buffer[0]<<" -> Reply";
        }
        
        ///--------Sender Mac----------------------
        bytesToRead=6;
        inputFile.seekg (22, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        cout<<endl<<"Sender Mac: ";
        
        for(int j=0; j<6; j++)
        {
            printf("%02x", (int)buffer[j]);
            if(j<5)
            {
                cout<<":";
            }
        }

        ///-----------Sender IP---------------------
        bytesToRead=4;
        inputFile.seekg (28, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        cout<<endl<<"Sender IP: ";
        
        for(int j=0; j<4; j++)
        {
            printf("%d", (int)buffer[j]);
            if(j<3)
            {
                cout<<".";
            }
        }

        ///-----------Target MAC----------------------
        bytesToRead=6;
        inputFile.seekg (32, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        cout<<endl<<"Target Mac: ";
        
        for(int j=0; j<6; j++)
        {
            printf("%02x", (int)buffer[j]);
            if(j<5)
            {
                cout<<":";
            }
        }

        ///------------Target IP----------------------
        bytesToRead=4;
        inputFile.seekg (38, ios::beg);
        inputFile.read ((char*)buffer, bytesToRead);
        
        cout<<endl<<"Target IP: ";
        
        for(int j=0; j<4; j++)
        {
            printf("%d", (int)buffer[j]);
            if(j<3)
            {
                cout<<".";
            }
        }

        delete[] buffer;
    }
    
    inputFile.close();
}

#endif // ARP_H_INCLUDED
