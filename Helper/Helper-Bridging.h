#include <pcap/pcap.h>

// Apple libpcap extensions (exported by the SDK's libpcap, not in its public headers): ask for the pktap
// pseudo-device, whose packets carry the sending/receiving process.
int pcap_set_want_pktap(pcap_t *, int);
