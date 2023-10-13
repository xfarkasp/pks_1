#pragma once
#include "PcapParser.h"

using namespace std;

std::map<unsigned int, std::string> PcapParser::setProtocolMap(std::string protocolFilePath, bool isHexa) {
    std::fstream protocolFile;
    std::map<unsigned int, std::string> mapName;
    try {
        protocolFile.open(protocolFilePath, ios::in); 

        if (protocolFile.is_open()) {

            std::string fileStr; //read lines from file to this string
            while (getline(protocolFile, fileStr)) { //read lines from file
                std::stringstream sBuffer;
                std::vector<std::string> splitString;
                //stream line from file to stringstream
                sBuffer << fileStr;
                //split input format to 2 parts devided by ':' and map value with protocol name
                while (getline(sBuffer, fileStr, ':')) {
                    splitString.push_back(fileStr);
                }
                if (splitString.size() != 0) {
                    if(isHexa)
                        mapName.insert({ stoi(splitString.at(0), 0, 16), splitString.at(1) }); //add to map protocol value in hexa and name 
                    else
                        mapName.insert({ stoi(splitString.at(0)), splitString.at(1) }); //add to map protocol value in decimal and name
                }
            }
            protocolFile.close(); //close protocol file
        }
        else
            throw -1;
    }
    catch (int error) {
        if(error == -1)
            std::cout << "error opening file, terminating" << endl;
        exit(0);
    }
    catch (...) {
        std::cout << "something went wrong, terminating" << endl;
        exit(0);
    }
    return mapName;
}

void PcapParser::parseFrame(std::string path) {
    _fileName = path;   //sets file current file path as member

    _protocolMap = setProtocolMap("Protocols\\L2.txt", true);  //call method to map protocols from file
    _portMap = setProtocolMap("Protocols\\ports.txt", false);  //call method to map protocols from file

    char errBuff[PCAP_ERRBUF_SIZE]; //error buffer for readinf pcap file

    if (pcap_t* pcap = pcap_open_offline(path.c_str(), errBuff)) //read file content to pcap_t pointer
    {
        struct pcap_pkthdr* header; //header structure from libpcap

        const u_char* data; // pointer to hex dump

        size_t packetCount = 0;

        while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) //read next frame in memory
        {
            Frame thisFrame;
            stringstream frameBuffer;

            thisFrame.index = ++packetCount;
            thisFrame.capLen = header->caplen;

            //if pcap len smaller than 60, padding was not detected, set length to min frame lengts
            if(header->len < 60)
                thisFrame.wireLen = 64;
            else
                thisFrame.wireLen = (header->len) + 4; // +4 FCS

            //put hexa frame bytes to vector
            std::vector<unsigned int> hexFrame;
            for (size_t i = 0; i < header->caplen; i++)
                hexFrame.push_back(data[i]);

            thisFrame.hexFrame = hexFrame;

            //check ISL frame
            std::stringstream islStream;
            for (int i = 0; i < 6; i++) {
                char  hex_string[20];
                sprintf_s(hex_string, "%.2X", hexFrame[i]); //convert byte from frame to hexa
                islStream << hex_string;
            }

            if (islStream.str() == "01000C000000") {
                thisFrame.isISL = true;
                for (size_t i = ISL_DEST_MAC_START; i < ISL_ETH_TYPE_END; i++)
                {
                    //pushback dest mac bytes to vector
                    if (FRAME_OFF_SETS::ISL_DEST_MAC_START <= i && i < FRAME_OFF_SETS::ISL_DEST_MAC_END)
                        thisFrame.destMac.push_back(hexFrame[i]);

                    //pushback source mac bytes to vector
                    if (FRAME_OFF_SETS::ISL_SRC_MAC_START <= i && i < FRAME_OFF_SETS::ISL_SRC_MAC_END)
                        thisFrame.srcMac.push_back(hexFrame[i]);

                    //get size of ethernet type bytes
                    if (ISL_ETH_TYPE_START <= i && i < ISL_ETH_TYPE_END) {
                        char  hex_string[20];
                        sprintf_s(hex_string, "%.2X", hexFrame[i]);
                        frameBuffer << hex_string;
                    }
                }
            }
            else {
                int arpOffSetSrc = 0;
                int arpOffSetDst = 0;
                for (size_t i = 0; i < (DST_IP_END + arpOffSetDst); i++)
                {
                    //pushback dest mac bytes to vector
                    if (FRAME_OFF_SETS::DEST_MAC_START <= i && i < FRAME_OFF_SETS::DEST_MAC_END)
                        thisFrame.destMac.push_back(hexFrame[i]);

                    //pushback source mac bytes to vector
                    if (FRAME_OFF_SETS::SOURCE_MAC_START <= i && i < FRAME_OFF_SETS::SOURCE_MAC_END)
                        thisFrame.srcMac.push_back(hexFrame[i]);

                    
                    //get size of ethernet type bytes
                    if (ETH_TYPE_START <= i && i < ETH_TYPE_END) {
                        char  hex_string[20];
                        sprintf_s(hex_string, "%.2X", hexFrame[i]);
                        frameBuffer << hex_string;
                    }
                    if (ETH_TYPE_END == i) {
                        //put data to frame struct
                        thisFrame.typeSize = stoi(frameBuffer.str(), 0, 16);
                        if (thisFrame.typeSize == 0x0806) {
                            arpOffSetSrc = ARP_SRC_IP_OFFSET;
                            arpOffSetDst = ARP_DST_IP_OFFSET;
                        }
                    }

                    //src ip adress
                    if ((SRC_IP_START + arpOffSetSrc) <= i && i < (DST_IP_START + arpOffSetSrc))
                        thisFrame.srcIp.push_back(hexFrame[i]);

                    //dst ip adress
                    if ((DST_IP_START + arpOffSetDst) <= i && i < (DST_IP_END + arpOffSetDst))
                        thisFrame.dstIp.push_back(hexFrame[i]);
                }

            }
            //IHL 
            frameBuffer.str("");
            frameBuffer.clear();
            if (thisFrame.typeSize == 0x0800) {
                unsigned int ihl = (hexFrame[14] & 0x0F) * 4;
                int offSet = 0;
                if (ihl < 20)
                    offSet = ihl;

                for (int i = SRC_PORT_START + offSet; i <= SRC_PORT_END + offSet; i++) {
                    char  hex_string[20];
                    sprintf_s(hex_string, "%.2X", hexFrame[i]);
                    frameBuffer << hex_string;
                }
                thisFrame.srcPort = stoi(frameBuffer.str(), 0, 16);

                frameBuffer.str("");
                frameBuffer.clear();
                for (int i = DST_PORT_START + offSet; i <= DST_PORT_END + offSet; i++) {
                    char  hex_string[20];
                    sprintf_s(hex_string, "%.2X", hexFrame[i]);
                    frameBuffer << hex_string;
                }
                thisFrame.dstPort = stoi(frameBuffer.str(), 0, 16);
            }

            //add this frame to vector of frames
            _frames.push_back(thisFrame);
        }
    }
    else {
        std::cout << "can not open pcap file, terminating!" << std::endl;
        exit(0);
    }
}

std::vector<std::string> PcapParser::getFrameType(int typeSize, std::vector<unsigned int> data, bool ISL) {
    std::vector<std::string> frameTypes;
    if (typeSize >= PcapParser::ETHERNET_II_MIN) {
        frameTypes.push_back("ETHERNET II");
        frameTypes.push_back(_protocolMap[typeSize]);
        return frameTypes;
    }
    else if (typeSize <= PcapParser::IEEE_802_3_MAX) {
        std::stringstream sBuffer;
        char  hex_string[20];
        if(!ISL)
            sprintf_s(hex_string, "%.2X", data[ETH_TYPE_END]); //convert number to hex
        else
            sprintf_s(hex_string, "%.2X", data[ISL_ETH_TYPE_END]); //convert number to hex

        switch (unsigned int typeSize = stoi(hex_string, 0, 16))
        {
        case IEEE_802_3_SNAP:
            frameTypes.push_back("IEEE 802.3 LLC & SNAP");
            if (!ISL){
                for (size_t i = SNAP_PID_START; i <= SNAP_PID_END; i++) {
                    sprintf_s(hex_string, "%.2X", data[i]);
                    sBuffer << hex_string;
                }
            }
            else {
                for (size_t i = ISL_SNAP_PID_START; i <= ISL_SNAP_PID_END; i++) {
                    sprintf_s(hex_string, "%.2X", data[i]);
                    sBuffer << hex_string;
                }
            }
            frameTypes.push_back(_protocolMap[stoi(sBuffer.str(), 0, 16)]);
            return frameTypes;

        case IEEE_802_3_RAW:
            frameTypes.push_back("IEEE 802.3 RAW");
            return frameTypes;

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
        std::cout << (getFrameType(frame.typeSize, frame.hexFrame, frame.isISL))[0] << endl;

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
            printf("%.2x ", frame.hexFrame[i]);
        }
        cout << endl << endl;
    }
}

std::vector<std::string> getMaxPacketSenders(std::map<std::string, unsigned int> map) {
    std::vector<std::string> ipMaxSenders;
    size_t prevMax = 0;
    while (!map.empty()) {
        size_t maxSentCount = 0;
        std::string ipKey = "";
        for (auto map : map) {
            if (map.second > maxSentCount) {
                ipKey = map.first;
                maxSentCount = map.second;
            }
        }
        if (prevMax != 0 && prevMax > maxSentCount)
            break;

        ipMaxSenders.push_back(ipKey);
        map.erase(ipKey);
        prevMax = maxSentCount;
    }
    return ipMaxSenders;
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
        output << YAML::Key << "len_frame_medium" << YAML::Value << packet.wireLen;
        std::vector<std::string> frameTypes = getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        output << YAML::Key << "frame_type" << YAML::Value << frameTypes.at(0);

        std::stringstream sBuffer;
        for (auto srcByte : packet.srcMac) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", srcByte);
            sBuffer << hex_string << ":";
        }
        output << YAML::Key << "src_mac" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);

        sBuffer.str("");
        sBuffer.clear();
        for (auto srcByte : packet.destMac) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", srcByte);
            sBuffer << hex_string << ":";
        }
        output << YAML::Key << "dst_mac" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);

        //frame types
        if (frameTypes.size() == 2) {
            if(frameTypes.at(0) == "IEEE 802.3 LLC & SNAP")
                output << YAML::Key << "pid" << YAML::Value << frameTypes.at(1);
            else if(frameTypes.at(0) == "IEEE 802.3 LLC")
                output << YAML::Key << "sap" << YAML::Value << frameTypes.at(1);
            else if (frameTypes.at(0) == "ETHERNET II") {
                output << YAML::Key << "ether_type" << YAML::Value << frameTypes.at(1);
            }
        }
        sBuffer.str("");
        sBuffer.clear();
        //source ip
        for(auto byte : packet.srcIp){
            sBuffer << byte << ".";
        }
        std::string srcString = sBuffer.str().erase(sBuffer.str().size() - 1); //src adress is used more times than dst to count senders
        output << YAML::Key << "src_ip" << YAML::Key << srcString;

        

        sBuffer.str("");
        sBuffer.clear();
        //dst ip
        for (auto byte : packet.dstIp) {
            sBuffer << byte << ".";
        }
        output << YAML::Key << "dst_ip" << YAML::Key << sBuffer.str().erase(sBuffer.str().size() - 1);

        if (frameTypes.at(1) == "IPv4") {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
            output << YAML::Key << "protocol" << YAML::Value << _protocolMap[stoi(hex_string, 0, 16)];
            output << YAML::Key << "src_port" << YAML::Value << packet.srcPort;
            output << YAML::Key << "dst_port" << YAML::Value << packet.dstPort;

            bool srcKnown = (_portMap.find(packet.srcPort) != _portMap.end());
            bool dstKnown = (_portMap.find(packet.dstPort) != _portMap.end());
            if (srcKnown && dstKnown)
                output << YAML::Key << "app_protocol" << YAML::Value << _portMap[packet.srcPort] + ", " + _portMap[packet.dstPort];
            else if (srcKnown)
                output << YAML::Key << "app_protocol" << YAML::Value << _portMap[packet.srcPort];
            else if (dstKnown)
                output << YAML::Key << "app_protocol" << YAML::Value << _portMap[packet.dstPort];

            //count ipv4 packet senders
            if (_packetSenders.find(srcString) != _packetSenders.end())
                _packetSenders[srcString]++;
            else {
                _packetSenders.insert({ srcString, 1 });
            }
        }

        sBuffer.str("");
        sBuffer.clear();
        for (size_t i = 0; i < packet.capLen; i++) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame[i]);
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

    output << YAML::Key << "ipv4_senders" << YAML::Value << YAML::BeginSeq;
    //print to yaml all sender packets and their values
    for (auto node : _packetSenders) {
        output << YAML::BeginMap;
        output << YAML::Key << "node" << YAML::Value << node.first;
        output << YAML::Key << "number_of_sent_packets" << YAML::Value << node.second;
        output << YAML::EndMap;
    }
    output << YAML::EndSeq;
    
    output << YAML::Key << "max_send_packets_by";
    output << YAML::Value << YAML::BeginSeq;

    for (auto node : getMaxPacketSenders(_packetSenders)){
        output << node;
    }

    output << YAML::EndSeq;

    output << YAML::EndMap;

    fstream yamlFile;
    yamlFile.open("yaml_output//" + _fileName.erase(_fileName.find('.'), _fileName.size() - 1) + "-output.yaml", ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _fileName << std::endl;
}

void PcapParser::serializeArpYaml() {
    std::map<unsigned int, std::string>arpOpcode = setProtocolMap("Protocols\\arp.txt", true);
    YAML::Emitter output;
    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/24"
        << YAML::Key << "pcap_name"
        << YAML::Value << _fileName.erase(0, _fileName.find_last_of("\\") + 1)
        << YAML::Key << "filter_name"
        << YAML::Value << "ARP";

    output << YAML::Key << "complete_comms" << YAML::Value << YAML::BeginSeq;
    output << YAML::BeginMap  << YAML::Key << "number_com" << YAML::Value << 0;
    output <<  YAML::Key << "packets" << YAML::Value << YAML::BeginSeq;

    //frames with arp maped to <reques, reply>
    std::vector<Frame>completeConnections;
    //frames waiting for reply
    std::vector<Frame> replyQue;
    for (auto packet : _frames) {
        std::vector<std::string> frameTypes = getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "ARP") {
            size_t indexOfFound = 0;
            for (auto quedFrame : replyQue) {
                if (packet.srcIp == quedFrame.dstIp) {
                   std::stringstream quedFrameBuffer;
                    std::stringstream newFrameBuffer;
                    char  hex_string[20];
                    for (size_t i = ARP_OPCODE_START; i <= ARP_OPCODE_END; i++) {
                        sprintf_s(hex_string, "%.2X", quedFrame.hexFrame.at(i));
                        quedFrameBuffer << hex_string;

                        sprintf_s(hex_string, "%.2X", packet.hexFrame.at(i));
                        newFrameBuffer << hex_string;
                    }
                    if (arpOpcode[stoi(quedFrameBuffer.str(), 0, 16)] == "REQUEST" && arpOpcode[stoi(newFrameBuffer.str(), 0, 16)] == "REPLY") {
                        completeConnections.push_back(quedFrame);
                        completeConnections.push_back(packet);
                        replyQue.erase(std::next(replyQue.begin(), indexOfFound));
                        break;
                    }
                    indexOfFound++;
                }
            }
            replyQue.push_back(packet);
        }
    }

    for (auto packet : completeConnections) {
        std::vector<std::string> frameTypes = getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "ARP") {
            output << YAML::BeginMap;
            output << YAML::Key << "frame_number" << YAML::Value << packet.index;
            output << YAML::Key << "len_frame_pcap" << YAML::Value << packet.capLen;
            output << YAML::Key << "len_frame_medium" << YAML::Value << packet.wireLen;
            std::vector<std::string> frameTypes = getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
            output << YAML::Key << "frame_type" << YAML::Value << frameTypes.at(0);

            std::stringstream sBuffer;
            for (auto srcByte : packet.srcMac) {
                char  hex_string[20];
                sprintf_s(hex_string, "%.2X", srcByte);
                sBuffer << hex_string << ":";
            }
            output << YAML::Key << "src_mac" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);

            sBuffer.str("");
            sBuffer.clear();
            for (auto srcByte : packet.destMac) {
                char  hex_string[20];
                sprintf_s(hex_string, "%.2X", srcByte);
                sBuffer << hex_string << ":";
            }
            output << YAML::Key << "dst_mac" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);

            sBuffer.str("");
            sBuffer.clear();
            //frame types
            if (frameTypes.size() == 2) {
                if (frameTypes.at(0) == "IEEE 802.3 LLC & SNAP")
                    output << YAML::Key << "pid" << YAML::Value << frameTypes.at(1);
                else if (frameTypes.at(0) == "IEEE 802.3 LLC")
                    output << YAML::Key << "sap" << YAML::Value << frameTypes.at(1);
                else if (frameTypes.at(0) == "ETHERNET II") {
                    output << YAML::Key << "ether_type" << YAML::Value << frameTypes.at(1);
                    if (frameTypes.at(1) == "ARP") {
                        char  hex_string[20];
                        for (size_t i = ARP_OPCODE_START; i <= ARP_OPCODE_END; i++) {
                            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(i));
                            sBuffer << hex_string;
                        }
                        
                        output << YAML::Key << "arp_opcode" << YAML::Value << arpOpcode[stoi(sBuffer.str(), 0, 16)];
                    }
                }
            }
            sBuffer.str("");
            sBuffer.clear();
            //source ip
            for (auto byte : packet.srcIp) {
                sBuffer << byte << ".";
            }
            std::string srcString = sBuffer.str().erase(sBuffer.str().size() - 1); //src adress is used more times than dst to count senders
            output << YAML::Key << "src_ip" << YAML::Key << srcString;



            sBuffer.str("");
            sBuffer.clear();
            //dst ip
            for (auto byte : packet.dstIp) {
                sBuffer << byte << ".";
            }
            output << YAML::Key << "dst_ip" << YAML::Key << sBuffer.str().erase(sBuffer.str().size() - 1);

            if (frameTypes.at(1) == "IPv4") {
                char  hex_string[20];
                sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
                output << YAML::Key << "protocol" << YAML::Value << _protocolMap[stoi(hex_string, 0, 16)];
                output << YAML::Key << "src_port" << YAML::Value << packet.srcPort;
                output << YAML::Key << "dst_port" << YAML::Value << packet.dstPort;

                bool srcKnown = (_portMap.find(packet.srcPort) != _portMap.end());
                bool dstKnown = (_portMap.find(packet.dstPort) != _portMap.end());
                if (srcKnown && dstKnown)
                    output << YAML::Key << "app_protocol" << YAML::Value << _portMap[packet.srcPort] + ", " + _portMap[packet.dstPort];
                else if (srcKnown)
                    output << YAML::Key << "app_protocol" << YAML::Value << _portMap[packet.srcPort];
                else if (dstKnown)
                    output << YAML::Key << "app_protocol" << YAML::Value << _portMap[packet.dstPort];

                //count ipv4 packet senders
                if (_packetSenders.find(srcString) != _packetSenders.end())
                    _packetSenders[srcString]++;
                else {
                    _packetSenders.insert({ srcString, 1 });
                }
            }

            sBuffer.str("");
            sBuffer.clear();
            for (size_t i = 0; i < packet.capLen; i++) {
                char  hex_string[20];
                sprintf_s(hex_string, "%.2X", packet.hexFrame[i]);
                sBuffer << hex_string;

                // next line after every 16 octets
                if (((i + 1) % 16) == 0 && i != 0) {
                    sBuffer << std::endl;
                }
                else {
                    if (i != packet.capLen - 1)
                        sBuffer << " ";
                }
            }
            if ((sBuffer.str()).at(((sBuffer.str()).size() - 1)) != '\n')
                sBuffer << endl;

            output << YAML::Key << "hexa_frame" << YAML::Value << YAML::Literal << sBuffer.str();
            output << YAML::EndMap;
        }
    }
    output << YAML::EndSeq;
    output << YAML::EndMap;

    fstream yamlFile;
    yamlFile.open("yaml_output//" + _fileName.erase(_fileName.find('.'), _fileName.size() - 1) + "-ARP.yaml", ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _fileName << std::endl;
}



