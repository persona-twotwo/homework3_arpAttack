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

class MyNet{
private:
	string myNetStatus;
	string myIP;
	string myIPBroad;
	string myMac;
	string gateway;
public:
	MyNet(string device){
		this->myNetStatus = execCommand("sh -c 'ip address show "+device+"'");
		int _tIndex1 = myNetStatus.find("inet")+5;
		int _tIndex2 = myNetStatus.find("/", _tIndex1);
		this->myIP = myNetStatus.substr(_tIndex1, _tIndex2 - _tIndex1);
		int _tIndex3 = myNetStatus.find("brd", _tIndex2)+4;
		int _tIndex4 = myNetStatus.find("scope", _tIndex3);
		this->myIPBroad = myNetStatus.substr(_tIndex3, _tIndex4 - _tIndex3 - 1);
		this->myMac = myNetStatus.substr(myNetStatus.find("link/ether")+11,17);
		this->gateway = execCommand("sh -c 'route |grep " + device + " |grep G'");
	}

	string getMyMac(){
		return this->myMac;
	}

	string getMyIP(){
		return this->myIP;
	}

	string getMyIPBroad(){
		return this->myIPBroad;
	}

	string getGateway(){
		return this->gateway;
	}


};

class ArpResource
{
public:
	string eth_smac;
	string eth_dmac;
	string arp_smac;
	string arp_tmac;
	string arp_sip;
	string arp_tip;
	ArpResource(
		string eth_smac,
		string eth_dmac,
		string arp_smac,
		string arp_tmac,
		string arp_sip,
		string arp_tip
		){
			this->eth_smac = eth_smac;
			this->eth_dmac = eth_dmac;
			this->arp_smac = arp_smac;
			this->arp_tmac = arp_tmac;
			this->arp_sip  = arp_sip;
			this->arp_tip  = arp_tip;
		}

};



string getMyIP(string dev){
	string myNet = execCommand("sh -c 'ip link show wlan0 | grep link/ether'");
	string myMac = myNet.substr(myNet.find("link/ether")+11,17);
	return myMac;
}


string getMyMAC(string dev){
	string myNet = execCommand("sh -c 'ip link show "+dev+" | grep link/ether'");
	string myMac = myNet.substr(myNet.find("link/ether")+11,17);
	return myMac;
}

int arpSend(char* dev, int type, ArpResource arpST){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("94:76:b7:f3:09:0a");
	packet.eth_.smac_ = Mac("a0:47:d7:11:53:91");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac("a0:47:d7:11:53:91");
	packet.arp_.sip_ = htonl(Ip("10.3.3.1"));
	packet.arp_.tmac_ = Mac("94:76:b7:f3:09:0a");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);

	return 0;
}

bool checkIP(string ip){
	vector<string> parts;
	int start = 0;
	int end = 0;
	int partCount = 0;
	for(int i = 0; i!=3; ++i){
		end = ip.find('.', start);
		if(end == string::npos){
			return false;
		}

		string part = ip.substr(start, end - start);

		if (part.empty() || part.size() > 3) {
            return false;
        }

        for (char c : part) {
            if (!isdigit(c)) {
                return false;
            }
        }

        int num = stoi(part);
        if (num < 0 || num > 255) {
            return false;
        }

        if (part.size() > 1) {
            return false;
        }

        start = end + 1;
	}
	string part = ip.substr(start);
    if (part.empty() || part.size() > 3) {
        return false;
    }

    for (char c : part) {
        if (!isdigit(c)) {
            return false;
        }
    }

    int num = stoi(part);
    if (num < 0 || num > 255) {
        return false;
    }

    if (part.size() > 1) {
        return false;
    }
	return true;
}


int main(int argc, char* argv[]) {
	if ((argc < 4) || (argc %2)) {
		usage();
		return -1;
	}
	vector<string> argument;
	for (int i = 2; i != argc; ++i){
		cout << argv[i] << endl;
		argument.push_back(argv[i]);
	}
	for (int i = 0; i != argument.size(); ++i){
		if(!checkIP(argument[i])) {
			usage();
			return(-1);	
		}
	}
	MyNet myNet = MyNet(argv[1]);
	
	cout << myNet.getGateway() << endl;
	cout << "myIP: " << myNet.getMyIP() << endl;
	cout << "myIPBroad: " << myNet.getMyIPBroad() << endl;
	cout << "myMac: " << myNet.getMyMac() << endl;
	map<string,string> mapOfIPMac;
	


}
