#pragma once
#include "PcapParser.h"

using namespace std;

void PcapParser::parseFrame(std::string path) {
    char errBuff[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_offline(path.c_str(), errBuff);

    struct pcap_pkthdr* header; //header structure from libpcap

    const u_char* data;

    size_t packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        Frame thisFrame;
        stringstream frameBuffer;
        thisFrame.hexDump = data;
        thisFrame.index = ++packetCount;
        thisFrame.capLen = header->caplen;
        thisFrame.wireLen = header->len;
        std::vector<unsigned int> destAdress;
        std::vector<unsigned int> srcAdress;

        for (size_t i = 0; i < ETH_TYPE_END; i++)
        { 
            //pushback dest mac bytes to vector
            if (FRAME_OFF_SETS::DEST_MAC_START <= i && i < FRAME_OFF_SETS::DEST_MAC_END)
                destAdress.push_back(data[i]);

            //pushback source mac bytes to vector
            if (FRAME_OFF_SETS::SOURCE_MAC_START <= i && i < FRAME_OFF_SETS::SOURCE_MAC_END)
                srcAdress.push_back(data[i]);

            //get size of ethernet type bytes
            if (ETH_TYPE_START <= i && i < ETH_TYPE_END)
                frameBuffer << data[i];
        }

        //put data to frame struct
        thisFrame.typeSize = frameBuffer.hex;
        thisFrame.destMac = destAdress;
        thisFrame.srcMac = srcAdress;

        //add this frame to vector of frames
        _frames.push_back(thisFrame);
    }
    //printData();
}

void PcapParser::getHexDump(const u_char* data, size_t pLen) {
    std::cout << "hexa_frame: ";
    for (size_t i = 0; i < pLen; i++){
        // next line after every 16 octets
        if ((i % 16) == 0)
            std::cout << std::endl;
        printf("%.2x ", data[i]);// Print each octet as hex (x), make sure there is always two characters (.2)
    }
    cout << endl << endl;
}

std::string PcapParser::getFrameType(int typeSize) {
    if (typeSize >= PcapParser::ETHERNET_II_MIN) {
        return "ETHERNET II";
    }
    else if (typeSize <= PcapParser::IEEE_802_3_MAX) {
        return "IEE 802.3";
    }
    return "undefined";
}

std::string PcapParser::getName(int typeSize) {
    switch (typeSize)
    {
    case 0x0200:
        return "XEROX PUB";
    case 0x0201:
        return "PUP Addr Trans";
    case 0x0800:
        return "IPv4";
    case 0x0801:
        return "X.75 Internet";
    case 0x0805:
        return "X.25 Level 3";
    case 0x0806:
        return "ARP";
    case 0x08035:
        return "RARP";
    case 0x0809B:
        return "Appletalk";
    case 0x080F3:
        return "AppleTalk AARP";
    case 0x8100:
        return "IEE 802.1Q VLAN-tagged frames";
    case 0x8137:
        return "Novell IPX";
    case 0x86DD:
        return "IPv6";
    case 0x880B:
        return "PPP";
    case 0x8847:
        return "MPLS";
    case 0x8848:
        return "MPLS with upstream-assigned label";
    case 0x8863:
        return "PPoE Discovery Stage";
    case 0x8864:
        return "PPoE Session Stage";
    default:
        return "not defined";
        break;
    }
}

void PcapParser::printData() {
    for (auto frame : _frames) {
        std::cout << "frame_number: " << frame.index << std::endl;
        std::cout << "len_frame_pcap: " << frame.capLen << std::endl;
        std::cout << "len_frame_medium: " << frame.wireLen << std::endl;
        std::cout << "frame_type: ";
        std::cout << getFrameType(frame.typeSize) << endl;

        std::cout << "src_mac: ";
        for(auto byte : frame.srcMac)
            printf("%.2x ", byte);

        std::cout << std::endl;

        std::cout << "dst_mac: ";
        for (auto byte : frame.destMac)
            printf("%.2x ", byte);

        std::cout << std::endl;

        //prints the hexdump in hexadecimal format formated 16 bytes per line
        getHexDump(frame.hexDump, frame.capLen);
    }
}

void PcapParser::serializeYaml() {
    YAML::Node action_1;
    action_1["name"] = "add";
    action_1["counts"] = 1000;

    YAML::Node action_2;
    action_2["name"] = "idle";
    action_2["counts"] = 10000;

    YAML::Node local_item;
    local_item["name"] = "adder";
    local_item["action_counts"].push_back(action_1);
    local_item["action_counts"].push_back(action_2);

    YAML::Node local;
    local.push_back(local_item);

    YAML::Emitter output;
    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/2024"
        << YAML::Key << "pcap_name"
        << YAML::Value << "place_holder.pcap";

    output << YAML::Key << "packets" << YAML::Value << YAML::BeginSeq;;
    
    for (auto packet : _frames) {
        output << YAML::BeginMap;
        //output << YAML::BeginSeq;
        //output << YAML::BeginMap;
        output << YAML::Key << "frame_number" << YAML::Value << packet.index;
        output << YAML::Key << "len_frame_pcap" << YAML::Value << packet.capLen;
        output << YAML::Key << "len_frame_wire" << YAML::Value << packet.capLen;

        std::stringstream sBuffer;
        for (auto srcByte : packet.srcMac) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", srcByte); //convert number to hex
            sBuffer << hex_string;
            if(srcByte != packet.srcMac.at(packet.srcMac.size()-1))
                sBuffer << ":";
        }
        output << YAML::Key << "src_mac" << YAML::Value << sBuffer.str();

        sBuffer.str("");
        sBuffer.clear();
        for (auto srcByte : packet.destMac) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", srcByte); //convert number to hex
            sBuffer << hex_string;
            if (srcByte != packet.destMac.at(packet.destMac.size() - 1))
                sBuffer << ":";
        }
        output << YAML::Key << "dst_mac" << YAML::Value << sBuffer.str();

        sBuffer.str("");
        sBuffer.clear();
        for (size_t i = 0; i < packet.capLen; i++) {
            // next line after every 16 octets
            if ((i % 16) == 0 && i !=0)
                sBuffer << std::endl;

            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexDump[i]); //convert number to hex
            sBuffer << hex_string << " ";
        }
        sBuffer << "\n";
        output << YAML::Key << "hexa_frame";
        output << YAML::Value << YAML::Literal << sBuffer.str();
        output << YAML::EndMap;
    }
    output << YAML::EndSeq;
    output << YAML::EndMap;

    fstream file0;
    file0.open("info.yaml", ios_base::out);
    if (file0.is_open())
    {
        file0 << output.c_str();
        file0.close();
    }
}