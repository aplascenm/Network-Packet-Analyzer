#ifndef PCAP_H_INCLUDED
#define PCAP_H_INCLUDED
#include <pcap.h>
#include <iostream>
using namespace std;

int pcap()
{   
    //Interface Information
    char *interfaceName;
    interfaceName = pcap_lookupdev(NULL);
    
    pcap_t *pcapSession;
    pcapSession = pcap_open_live(interfaceName,BUFSIZ,1,1000,NULL);
    
    if(pcapSession==NULL)
    {
        return -1;
    }
    
    if(pcap_datalink(pcapSession)!=DLT_EN10MB)
    {
        return -3;
    }
    
    const u_char *packetData;
    struct pcap_pkthdr packetHeader;

    packetData=pcap_next(pcapSession, &packetHeader);
    pcap_close(pcapSession);

    return 0;
}



#endif // PCAP_H_INCLUDED
