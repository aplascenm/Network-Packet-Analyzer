#ifndef FUNCIONES_H_INCLUDED
#define FUNCIONES_H_INCLUDED
#include <limits.h>
#include <sstream>
#include <iomanip>
#include <string.h>
#include <iostream>
#include <fstream>
#include "diccionario.h"
using namespace std;

void imprimir(char c)
{
    for (int i = 7; i >= 0; --i)
    {
        putchar( (c & (1 << i)) ? '1' : '0' );
    }

    putchar('\n');
}

char* chartobin ( unsigned char c )
{
    static char bin[CHAR_BIT + 1] = { 0 };
    int i;

    for ( i = CHAR_BIT - 1; i >= 0; i-- )
    {
        bin[i] = (c % 2) + '0';
        c /= 2;
    }

    return bin;
}

char* chartobin2 ( unsigned char c )
{
    static char bin[9] = { 0 };
    int i;

    for ( i = 7; i >= 0; i-- )
    {
        bin[i] = (c % 2) + '0';
        c /= 2;
    }

    return bin;
}

void cast (char *c)
{
    if(c[7]=='1')
    {
        cout<<" Es Multicast";
    }

    if(c[7]=='0')
    {
        cout<<" Es Unicast ";
    }
}

void direcciones (char *binaryHead)
{
    int size;
    size=6;
    
    unsigned char * buffer;
    ifstream file (binaryHead, ios::in|ios::binary);
    
    if(!file.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        buffer = new unsigned char [size];
        file.seekg (0, ios::beg);
        file.read ((char*)buffer, size);

        char *bin;
        
        //----------------Destino----------------------------------------------------------
        cout<<"Direccion Destino: ";
        for(int j=0; j<6; j++)
        {
            if(j==0)
            {
                bin=chartobin(buffer[j]);
            }
            printf("%02x", (int)buffer[j]);
            if(j==5)
            {
                cout<<" ->";
            }else
            {
                cout<<":";
            }
        }

        cast(bin);

        //--------------Origen--------------------------------------------------------------
        cout<<endl;
        file.seekg (6, ios::beg);
        file.read ((char*)buffer, size);
        
        cout<<"Direccion Origen: ";
        for(int j=0; j<6; j++)
        {
            if(j==0)
            {
                bin=chartobin(buffer[j]);
            }
            printf("%02x", (int)buffer[j]);
            if(j==5)
            {
                cout<<" ->";
            }else
            {
                cout<<":";
            }
        }

        cast(bin);
        
        delete[] buffer;
    }

    file.close();
}

void mac (char *binaryHead)
{
    ifstream::pos_type fileSize;
    unsigned char * fileBuffer;
    
    ifstream file (binaryHead, ios::in|ios::binary|ios::ate);
    
    if (file.is_open())
    {
        fileSize = file.tellg();
        fileBuffer = new unsigned char [fileSize];
        
        file.seekg (0, ios::beg);
        file.read ((char*)fileBuffer, fileSize);

        for (int l=0; l<fileSize; l++){
            //cout << (int)fileBuffer[l]<<endl;
            printf("%x", (int)fileBuffer[l]);
        }

        file.close();
        delete[] fileBuffer;

    }else
    {
        cout<<endl<<"Error."<<endl;
    }
}

void mostrarbin(char *binaryHead)
{
    char currentByte;
    char *bin;
    int byteCounter=0;
    
    ifstream inputFile(binaryHead);
    
    if(!inputFile.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        while(!inputFile.eof())
        {
            if(inputFile.eof())
            {
                break;
            }
            
            inputFile.get(currentByte);
            bin=chartobin(currentByte);
            
            cout<<bin<<endl;
            byteCounter++;
        }

        cout<<endl<<byteCounter<<endl;

    }

    inputFile.close();
}

string tipo(char *binaryHead)
{
    int size;
    size=2;
    unsigned char * buffer;
    
    ifstream inputFile (binaryHead, ios::in|ios::binary);
    
    if (inputFile.is_open())
    {
        buffer = new unsigned char [size];

        inputFile.seekg (12, ios::beg);
        inputFile.read ((char*)buffer, size);

        string hexString;
        stringstream hexStream;

        hexStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[0];
        hexStream<<hex<<setw(2)<<setfill('0')<<(int)buffer[1];
        
        hexString="0x"+hexStream.str();
        
        cout<<endl<<"Tipo: ";
        verificardE(hexString);
        
        //printf("\nTipo: 0x%02x%02x", (int)ch[0], (int)ch[1]);
        delete[] buffer;
        inputFile.close();

        return hexString;
    }else
    {
        cout<<endl<<"Error."<<endl;
        return "error";
    }

    inputFile.close();
    return "...";
}

void crc(char *binaryHead, int payloadLength)
{
    int size;
    size=4;
    unsigned char * buffer;
    
    ifstream inputFile (binaryHead, ios::in|ios::binary);
    
    if (inputFile.is_open())
    {
        buffer = new unsigned char [size];
        
        inputFile.seekg (payloadLength+14, ios::beg);
        inputFile.read ((char*)buffer, size);
        
        printf("\nCRC: 0x%02x%02x%02x%02x", (int)buffer[0], (int)buffer[1], (int)buffer[2], (int)buffer[3]);
        
        delete[] buffer;
    }else
    {
        cout<<endl<<"Error."<<endl;
    }
    
    inputFile.close();
}

#endif // FUNCIONES_H_INCLUDED
