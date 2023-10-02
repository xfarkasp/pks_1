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
    _fileName = path;   //sets file current file path as member

    setProtocolMap();   
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
        thisFrame.wireLen = header->len + 4;
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

        switch (unsigned int typeSize = stoi(hex_string, 0, 16))
        {
        case IEEE_802_3_SNAP:
            frameTypes.push_back("IEEE 802.3 LLC & SNAP");
            for (size_t i = 20; i < 22; i++) {
                sprintf_s(hex_string, "%.2X", data[i]);
                sBuffer << hex_string;
            }
            frameTypes.push_back(_protocolMap[stoi(sBuffer.str(), 0, 16)]);
            return frameTypes;
        case IEEE_802_3_RAW:
            frameTypes.push_back("IEEE 802.3 RAW");
        default:
            frameTypes.push_back("IEEE 802.3 LLC");
            frameTypes.push_back(_protocolMap[typeSize]);
            return frameTypes;
        }
    }
    frameTypes.push_back("undefined");
    return frameTypes;
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

        std::cout << "hexa_frame: ";
        for (size_t i = 0; i < frame.hexFrame.size(); i++) {
            // next line after every 16 octets
            if ((i % 16) == 0)
                std::cout << std::endl;
            printf("%.2x ", frame.hexFrame[i]);// Print each octet as hex (x), make sure there is always two characters (.2)
        }
        cout << endl << endl;
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

        if (frameTypes.size() == 2) {
            if(frameTypes.at(0) == "IEEE 802.3 LLC & SNAP")
                output << YAML::Key << "pid" << YAML::Value << frameTypes.at(1);
            else if(frameTypes.at(0) == "IEEE 802.3 LLC")
                output << YAML::Key << "pid" << YAML::Value << frameTypes.at(1);
        }
            
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
        if((sBuffer.str()).at(((sBuffer.str()).size()-1)) != '\n')
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