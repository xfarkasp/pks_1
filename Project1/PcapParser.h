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
        void parseFrame(std::string path);  //parses pcap file
        void printData();       //prints data to console from pcap
        void serializeYaml();   //serializes read value to yaml
    
    private:
        void setProtocolMap();  //sets the protocol maping from external file
        std::vector<std::string> getFrameType(int typeSize, std::vector<unsigned int>);

    private:
        enum FRAME_OFF_SETS {
            DEST_MAC_START = 0,
            DEST_MAC_END = 6,
            SOURCE_MAC_START = 6,
            SOURCE_MAC_END = 12,
            ETH_TYPE_START = 12,
            ETH_TYPE_END = 14,
            SNAP_PID_START = 20,
            SNAP_PID_END = 21,
        };

        enum FRAME_TYPE {
            ETHERNET_II_MIN = 1536, //min value of Ethernet II frame
            IEEE_802_3_MAX = 1500,  //max value of Ethernet II frame
            IEEE_802_3_SNAP = 0xAA,
            IEEE_802_3_RAW = 0xFF,
        };

        private:
            std::vector<Frame> _frames;
            std::string _fileName;
            std::map<unsigned int, std::string> _protocolMap;
};