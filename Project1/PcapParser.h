#pragma once
#include <pcap.h>
#include <iostream>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>

struct Frame {
    size_t index;
    unsigned int capLen;
    unsigned int wireLen;
    std::vector<unsigned int> hexFrame;
    std::vector<unsigned int> destMac;
    std::vector<unsigned int> srcMac;
    int typeSize;
};

class PcapParser {
	public:
        void parseFrame(std::string path);
		static void getHexDump(std::vector<unsigned int> data);
        std::string getFrameType(int typeSize, std::vector<unsigned int>);
        static std::string getName(int typeSize);
        void printData();
        void serializeYaml();

    private:
        enum FRAME_OFF_SETS {
            DEST_MAC_START = 0,
            DEST_MAC_END = 6,
            SOURCE_MAC_START = 6,
            SOURCE_MAC_END = 12,
            ETH_TYPE_START = 12,
            ETH_TYPE_END = 14,
        };

        enum FRAME_TYPE {
            ETHERNET_II_MIN = 1536,
            IEEE_802_3_MAX = 1500,
            IEEE_802_3_SNAP = 0xAA,
            IEEE_802_3_RAW = 0xFF,
        };

        enum ETH_TYPE {
            XEROX_PUP = 0x0200, //512
            PUP_ADDR_TRANS = 0x0201, //513
            IPV4 = 0x0800, //2048
            X75_INTERNET = 0x0801,//2049
            X25_LVL3 = 0x0805, //2053
            ARP = 0x0806, //2054
            RARP = 0x08035, //32821
            APPLE_TALK = 0x0809B,
            APPLE_TALK_AARP = 0x080F3,
            IEE8021Q = 0x8100,
            NOVELL_IPX = 0x8137,
            IPV6 = 0x86DD,
            PPP = 0x880B,
            MPLS = 0x8847,
            MPLS_UP_STREAM = 0x8848,
            PPPOE_DISCOVERY = 0x8863,
            PPPOE_SESSION = 0x8864
        };

        enum LLC802_2_SAP {
            NULL_SAP = 0x00,
            LLC_SM_INDIVIDUAL = 0x02,
            LLC_SUBLAYER = 0x03,
            IP_DOD = 0x06,
            PROWAY_IEC955_NM = 0xDE,
            BPDU = 0x42,
            MMS = 0x4E,
            ISI_IP = 0x5E,
            x_25_PLP = 0x7E,
            PROWAY_IEC955_AS = 0x8E,
            SNAP = 0xAA,
            IPX = 0xE0,
            LAN_MANAGEMENT = 0xF4,
            ISO_NETWORK_LAYER = 0xFE,
            GLOBAL_DSAP = 0xFF
        };

        private:
            std::vector<Frame> _frames;
            std::string _fileName;
};