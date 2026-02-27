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

void dscpEcn(char *c)
{
    string s;
    stringstream ss, ss2;
    int n;
    char *cc;
    for(int i=0; i<6; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    n=strtoull(s.c_str(), &cc, 2);
    cout<<endl<<"DSCP: "<<n;
    if(c[6]=='1')
    {
        cout<<endl<<"ECN bit 1: ON";
    }else
    {
        cout<<endl<<"ECN bit 1: OFF";
    }
    if(c[7]=='1')
    {
        cout<<endl<<"ECN bit 2: ON";
    }else
    {
        cout<<endl<<"ECN bit 2: OFF";
    }
}
void flags (char *c)
{
    if(c[0]=='1')
    {
        cout<<endl<<"MSB Reservado: ON";
    }else
    {
        cout<<endl<<"MSB Reservado: OFF";
    }
    if(c[1]=='1')
    {
        cout<<endl<<"More Fragments: ON";
    }else
    {
        cout<<endl<<"More Fragments: OFF";
    }
    if(c[2]=='1')
    {
        cout<<endl<<"Dont Fragments: ON";
    }else
    {
        cout<<endl<<"Dont Fragments: OFF";
    }
}
void fragmetsOffset(char *c, char *c2)
{
    string s;
    stringstream ss, ss2;
    int n, n2;
    char *cc;
    for(int i=3; i<8; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    n=strtoull(s.c_str(), &cc, 2);
    for(int i=0; i<8; i++)
    {
        ss2<<c2[i];
    }
    s=ss.str();
    n2=strtoull(s.c_str(), &cc, 2);
    cout<<endl<<"Fragment Offset: "<<n+n2;
}
void identificar(int n, char *c, int t)
{
    if(n==1)
    {
        icmp4(c,t);
    }else if(n==6)
    {
        //tcp(c);
    }
}

void ipv4(char *c)
{
    int tam;
    unsigned char * ch;
    ifstream ar (c, ios::in|ios::binary);
    if(!ar.is_open())
    {
        cout<<endl<<"Error."<<endl;
    }else
    {
        cout<<endl<<"                IPV4                 "<<endl;
        char *bin, *bin2;
        ///-------MSB Y LSB----------------
        tam=1;
        int ihl;
        ch = new unsigned char [tam];
        ar.seekg (14, ios::beg);
        ar.read ((char*)ch, tam);
        bin=chartobin(ch[0]);
        ihl=versionIhl(bin);
        ///-------DSCP Y ECN---------------
        tam=1;
        ar.seekg (15, ios::beg);
        ar.read ((char*)ch, tam);
        bin=chartobin(ch[0]);
        dscpEcn(bin);
        ///-------Total Lenght-------------
        tam=2;
        ar.seekg (16, ios::beg);
        ar.read ((char*)ch, tam);
        string s;
        long int n;
        stringstream z;
        char *cc;
        bin=chartobin(ch[0]);
        z<<bin;
        bin=chartobin(ch[1]);
        z<<bin;
        s=z.str();
        n=strtoull(s.c_str(), &cc, 2);
        cout<<endl<<"Total Lenght: "<<n-ihl;
        int t=n-ihl;
        ///------Identification------------
        tam=2;
        ar.seekg (18, ios::beg);
        ar.read ((char*)ch, tam);
        stringstream z2;
        bin=chartobin(ch[0]);
        z2<<bin;
        bin=chartobin(ch[1]);
        z2<<bin;
        s=z2.str();
        n=strtoull(s.c_str(), &cc, 2);
        cout<<endl<<"Identification: "<<n;
        ///---------FLAGS-------------------
        tam=1;
        ar.seekg (20, ios::beg);
        ar.read ((char*)ch, tam);
        bin=chartobin(ch[0]);
        flags(bin);
        ///---------Fragment Offset---------
        tam=2;
        ar.seekg (20, ios::beg);
        ar.read ((char*)ch, tam);
        bin=chartobin(ch[0]);
        bin2=chartobin(ch[1]);
        fragmetsOffset(bin, bin2);
        ///----------Time To Life-----------
        tam=1;
        ar.seekg (22, ios::beg);
        ar.read ((char*)ch, tam);
        cout<<endl<<"Time to life: "<<(int)ch[0];
        ///---------Protocol----------------
        int num;
        tam=1;
        ar.seekg (23, ios::beg);
        ar.read ((char*)ch, tam);
        stringstream ss;
        ss<<(int)ch[0];
        s=ss.str();
        num=verificarIPT(s);
        ///--------Header Checksum----------
        tam=2;
        ar.seekg (24, ios::beg);
        ar.read ((char*)ch, tam);
        stringstream sss;
        sss<<hex<<setw(2)<<setfill('0')<<(int)ch[0];
        sss<<hex<<setw(2)<<setfill('0')<<(int)ch[1];
        s="0x"+sss.str();
        cout<<endl<<"Header Checksum: "<<s;
        ///---------Direccion Origen-----------
        tam=4;
        ar.seekg (26, ios::beg);
        ar.read ((char*)ch, tam);
        cout<<endl<<"Sender IP: ";
        for(int j=0; j<4; j++)
        {
            printf("%d", (int)ch[j]);
            if(j<3)
            {
                cout<<".";
            }
        }
        ///---------Direccion Destino----------
        tam=4;
        ar.seekg (30, ios::beg);
        ar.read ((char*)ch, tam);
        cout<<endl<<"Tarjet IP: ";
        for(int j=0; j<4; j++)
        {
            printf("%d", (int)ch[j]);
            if(j<3)
            {
                cout<<".";
            }
        }
        ///-----------Data----------------------
        identificar(num, c,t);
    }
    delete[] ch;
    ar.close();
}
#endif // IPV4_H_INCLUDED
