#pragma once
#include <pcap.h>
#include <iostream>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>

//struct of an ethernet frame
struct Frame {
    size_t index;
    size_t udpPayload;
    size_t tftpBlockCount =SIZE_MAX;
    unsigned int capLen;
    unsigned int wireLen;
    unsigned int srcPort;
    unsigned int dstPort;
    unsigned int ihlOffset = 0;
    int icmpID = -1;
    int icmpSQ = -1;
    int fragID = -1;
    int fragOffSet = -1;
    std::string arpOpcode;
    std::string tftpOptcode;
    std::string icmpType;
    std::vector<unsigned int> hexFrame;
    std::vector<unsigned int> destMac;
    std::vector<unsigned int> srcMac;
    std::vector<unsigned int> srcIp;
    std::vector<unsigned int> dstIp;
    int typeSize;
    bool isISL = false;
    bool MF = false;
};

class PcapParser {
	public:
        void parseFrame(std::string path);  //parses pcap file
        void printData();       //prints data to console from pcap
        void serializeYaml();   //serializes read value to yaml
        void arpFilter();       //arpFilter 
        void icmpFilter();
        void tftpFilter();
        std::map<unsigned int, std::string> setProtocolMap(std::string protocolFilePath, bool isHexa);  //sets the protocol maping from external file
        std::vector<std::string> getFrameType(int typeSize, std::vector<unsigned int>, bool ISL); //returns vector of strings with frame type and pid/sap

    protected:
        //frame offset enumeration
        enum FRAME_OFF_SETS {
            DEST_MAC_START = 0,
            DEST_MAC_END = 6,
            SOURCE_MAC_START = 6,
            SOURCE_MAC_END = 12,
            ETH_TYPE_START = 12,
            ETH_TYPE_END = 14,
            SNAP_PID_START = 20,
            SNAP_PID_END = 21,

            SRC_IP_START = 26,
            DST_IP_START = 30,
            DST_IP_END = 34,

            SRC_PORT_START = 34,
            SRC_PORT_END = 35,
            DST_PORT_START = 36,
            DST_PORT_END = 37,

            ICMP_TYPE = 34,
            ICMP_CODE = 35,

            ICMP_IDENT_START = 38,
            ICMP_IDENT_END = 39,

            ICMP_SEQ_START = 40,
            ICMP_SEQ_END = 41,

            ICMP_IDENT_EXCEEDED_START = 66,
            ICMP_IDENT_EXCEEDED_END = 67,

            ICMP_SEQ_EXCEEDED_START = 68,
            ICMP_SEQ_EXCEEDED_END = 69,

            //fragmentation positions
            FRAG_FLAG = 20,
            RB_Flag = 0,
            DF_Flag = 1,
            MF_Flag = 2,
            FRAG_ID_START = 18,
            FRAG_ID_END = 19,
            FRAG_OFFSET_START = 20,
            FRAG_OFFSET_END = 21,

            //tftp positions 38 39
            TFTP_OPCODE = 43,
            UDP_PAYLOAD_SIZE_START = 38,
            UDP_PAYLOAD_SIZE_END = 39,
            TFTP_DEFAULT_SIZE = 512,

            EPHEMERAL_PORT_START = 49152,
            EPHEMERAL_PORT_END = 65535,

            ARP_SRC_IP_OFFSET = 2,
            ARP_DST_IP_OFFSET = 8,
            //ISL frame
            ISL_DEST_MAC_START = 26,
            ISL_DEST_MAC_END = 32,
            ISL_SRC_MAC_START = 32,
            ISL_SRC_MAC_END = 38,
            ISL_ETH_TYPE_START = 38,
            ISL_ETH_TYPE_END = 40,
            ISL_SNAP_PID_START = 46,
            ISL_SNAP_PID_END = 47,

            //arp reply-request 20-21
            ARP_OPCODE_START = 20,
            ARP_OPCODE_END = 21,
        };
        //frame type values
        enum FRAME_TYPE {
            ETHERNET_II_MIN = 1536, //min value of Ethernet II frame
            IEEE_802_3_MAX = 1500,  //max value of Ethernet II frame
            IEEE_802_3_SNAP = 0xAA,
            IEEE_802_3_RAW = 0xFF,
        };

        public:
            std::vector<Frame> _frames; //vector of all parsed frames
            std::string _fileName;  //current file name
            std::map<unsigned int, std::string> _protocolMap; //map of protocol values and names
            std::map<unsigned int, std::string> _portMap; //map of protocol values and names
            std::map<unsigned int, std::string> _arpMap;
            std::map<unsigned int, std::string> _icmpMap;
            std::map<std::string, unsigned int> _packetSenders; //map of sender ips and packets sent value
};