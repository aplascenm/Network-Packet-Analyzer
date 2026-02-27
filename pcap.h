#ifndef PCAP_H_INCLUDED
#define PCAP_H_INCLUDED
#include <pcap.h>
#include <iostream>
using namespace std;

int pcap()
{
    char *dev;
    dev=pcap_lookupdev(NULL);
    pcap_t *sesion;
    sesion=pcap_open_live(dev,BUFSIZ,1,1000,NULL);
    if(sesion==NULL)
    {
        return -1;
    }
    if(pcap_datalink(sesion)!=DLT_EN10MB)
    {
        return -3;
    }
    const u_char *buffer;
    struct pcap_pkthdr header;
    buffer=pcap_next(sesion, &header);
    //cout<<endl<<"Longitud="<<header.len<<endl;
    pcap_close(sesion);
    return 0;
}



#endif // PCAP_H_INCLUDED
