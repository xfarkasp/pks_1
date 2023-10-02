#pragma once
#include "PcapParser.h"

using namespace std;

void PcapParser::setProtocolMap() {
    std::fstream protocolFile;
    std::string protocolFilePath = "C:\\Users\\lordp\\source\\repos\\Project1\\Project1\\protocols.txt";

    protocolFile.open(protocolFilePath, ios::in); //open a file to perform read operation using file object
    if (protocolFile.is_open()) {   //checking whether the file is open
        std::string fileStr;
        while (getline(protocolFile, fileStr)) { //read data from file object and put it into string.
            std::stringstream sBuffer;
            std::vector<std::string> splitString;

            sBuffer << fileStr;
            while (getline(sBuffer, fileStr, ':')) {
                splitString.push_back(fileStr);
            }
            if (splitString.size() != 0) {
                _protocolMap.insert({ stoi(splitString.at(0), 0, 16), splitString.at(1)});
            }
        }
        protocolFile.close(); //close the file object.
    }
}

void PcapParser::parseFrame(std::string path) {
    _fileName = path;
    char errBuff[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_offline(path.c_str(), errBuff);

    struct pcap_pkthdr* header; //header structure from libpcap

    const u_char* data;

    size_t packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        Frame thisFrame;
        stringstream frameBuffer;
        thisFrame.index = ++packetCount;
        thisFrame.capLen = header->caplen;
        thisFrame.wireLen = header->len;
        std::vector<unsigned int> destAdress;
        std::vector<unsigned int> srcAdress;

        std::vector<unsigned int> hexFrame;
        for (size_t i = 0; i < header->caplen; i++)
            hexFrame.push_back(data[i]);

        thisFrame.hexFrame = hexFrame;

        for (size_t i = 0; i < ETH_TYPE_END; i++)
        {
            //pushback dest mac bytes to vector
            if (FRAME_OFF_SETS::DEST_MAC_START <= i && i < FRAME_OFF_SETS::DEST_MAC_END)
                destAdress.push_back(hexFrame[i]);

            //pushback source mac bytes to vector
            if (FRAME_OFF_SETS::SOURCE_MAC_START <= i && i < FRAME_OFF_SETS::SOURCE_MAC_END)
                srcAdress.push_back(hexFrame[i]);

            //get size of ethernet type bytes
            if (ETH_TYPE_START <= i && i < ETH_TYPE_END) {
                char  hex_string[20];
                sprintf_s(hex_string, "%.2X", hexFrame[i]); //convert number to hex
                frameBuffer << hex_string;
            }
        }
        //put data to frame struct
        thisFrame.typeSize = stoi(frameBuffer.str(), 0, 16);
        thisFrame.destMac = destAdress;
        thisFrame.srcMac = srcAdress;

        //add this frame to vector of frames
        _frames.push_back(thisFrame);
    }
    //printData();
}

void PcapParser::getHexDump(std::vector<unsigned int> data) {
    std::cout << "hexa_frame: ";
    for (size_t i = 0; i < data.size(); i++) {
        // next line after every 16 octets
        if ((i % 16) == 0)
            std::cout << std::endl;
        printf("%.2x ", data[i]);// Print each octet as hex (x), make sure there is always two characters (.2)
    }
    cout << endl << endl;
}

std::vector<std::string> PcapParser::getFrameType(int typeSize, std::vector<unsigned int> data) {
    std::vector<std::string> frameTypes;
    if (typeSize >= PcapParser::ETHERNET_II_MIN) {
        frameTypes.push_back("ETHERNET II");
        return frameTypes;
    }
    else if (typeSize <= PcapParser::IEEE_802_3_MAX) {
        std::stringstream sBuffer;
        char  hex_string[20];
        sprintf_s(hex_string, "%.2X", data[14]); //convert number to hex

        switch (stoi(hex_string, 0, 16))
        {
        case IEEE_802_3_SNAP:
            frameTypes.push_back("IEEE 802.3 LLC & SNAP");
            for (size_t i = 20; i < 22; i++) {
                sprintf_s(hex_string, "%.2X", data[i]);
                sBuffer << hex_string;
            }
            frameTypes.push_back(getName(stoi(sBuffer.str(), 0, 16)));
            return frameTypes;
        case IEEE_802_3_RAW:
            frameTypes.push_back("IEEE 802.3 RAW");
        default:
            frameTypes.push_back("IEEE 802.3 LLC");
        }
    }
    frameTypes.push_back("undefined");
    return frameTypes;
}

std::string PcapParser::getName(int typeSize) {
    switch (typeSize)
    {
    //saps
    case 0x00:
        return "Null SAP";
    case 0x02:
        return "LLC Sublayer Management / Individual";
    case 0x03:
        return "LLC Sublayer Management / Group";
    case 0x06:
        return "IP (DoD Internet Protocol)";
    case 0x0E:
        return "PROWAY (IEC 955) Network Management, Maintenance and Installation";
    case 0x42:
        return "STP";
    case 0x4E:
        return "MMS (Manufacturing Message Service) EIA-RS 511";
    case 0x5E:
        return "ISI IP";
    case 0x7E:
        return "X.25 PLP (ISO 8208)";
    case 0x8E:
        return "PROWAY (IEC 955) Active Station List Maintenance";
    case 0xAA:
        return "SNAP (Sub-Network Access Protocol/ non-IEEE SAPS)";
    case 0xE0:
        return "IPX (Novell NetWare)";
    case 0xF4:
        return "LAN Management";
    case 0xFE:
        return "ISO Network Layer Protocols";
    case 0xFF:
        return "Global DSAP";
    //pids
    case 0x010B:
        return "PVSTP+";
    case 0x0200:
        return "XEROX PUB";
    case 0x0201:
        return "PUP Addr Trans";
    case 0x0208:
        return "RIP";
    case 0x0800:
        return "IP (IPv4)";
    case 0x0801:
        return "X.75 Internet";
    case 0x0805:
        return "X.25 Level 3";
    case 0x0806:
        return "ARP (Adress Resolution Protocol)";
    case 0x2000:
        return "CDP";
    case 0x2004:
        return "DTP";
    case 0x08035:
        return "RARP";
    case 0x0809B:
        return "Appletalk";
    case 0x080F3:
        return "AppleTalk AARP (Kinetics)";
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
    case 0x88CC:
        return "Link Layer Discovery Protocol (LLDP)";
    case 0x9000:
        return "Loopback";
    default:
        return "not defined";
    }
}

void PcapParser::printData() {
    for (auto frame : _frames) {
        std::cout << "frame_number: " << frame.index << std::endl;
        std::cout << "len_frame_pcap: " << frame.capLen << std::endl;
        std::cout << "len_frame_medium: " << frame.wireLen << std::endl;
        std::cout << "frame_type: ";
        std::cout << (getFrameType(frame.typeSize, frame.hexFrame))[0] << endl;

        std::cout << "src_mac: ";
        for(auto byte : frame.srcMac)
            printf("%.2x ", byte);

        std::cout << std::endl;

        std::cout << "dst_mac: ";
        for (auto byte : frame.destMac)
            printf("%.2x ", byte);

        std::cout << std::endl;

        //prints the hexdump in hexadecimal format formated 16 bytes per line
        getHexDump(frame.hexFrame);
    }
}

void PcapParser::serializeYaml() {
    YAML::Emitter output;
    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/24"
        << YAML::Key << "pcap_name"
        << YAML::Value << _fileName.erase(0, _fileName.find_last_of("\\") + 1);

    output << YAML::Key << "packets" << YAML::Value << YAML::BeginSeq;
    
    for (auto packet : _frames) {
        output << YAML::BeginMap;
        output << YAML::Key << "frame_number" << YAML::Value << packet.index;
        output << YAML::Key << "len_frame_pcap" << YAML::Value << packet.capLen;
        output << YAML::Key << "len_frame_medium" << YAML::Value << packet.capLen;
        std::vector<std::string> frameTypes = getFrameType(packet.typeSize, packet.hexFrame);
        output << YAML::Key << "frame_type" << YAML::Value << frameTypes.at(0);

        std::stringstream sBuffer;
        for (auto srcByte : packet.srcMac) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", srcByte); //convert number to hex
            sBuffer << hex_string << ":";

        }
        output << YAML::Key << "src_mac" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);

        sBuffer.str("");
        sBuffer.clear();
        for (auto srcByte : packet.destMac) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", srcByte); //convert number to hex
            sBuffer << hex_string << ":";
        }
        output << YAML::Key << "dst_mac" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);

        if(frameTypes.size() == 2 && frameTypes.at(0) == "IEEE 802.3 LLC & SNAP")
            output << YAML::Key << "pid" << YAML::Value <<  frameTypes.at(1);

        sBuffer.str("");
        sBuffer.clear();
        for (size_t i = 0; i < packet.capLen; i++) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame[i]); //convert number to hex
            sBuffer << hex_string;

            // next line after every 16 octets
            if (((i + 1) % 16) == 0 && i != 0) {
                sBuffer << std::endl;
            }
            else {
                if(i != packet.capLen - 1)
                    sBuffer << " ";
            }  
        }
        if((sBuffer.str()).at(((sBuffer.str()).size()-1) != '\n'))
            sBuffer << endl;
        output << YAML::Key << "hexa_frame" << YAML::Value << YAML::Literal << sBuffer.str();
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