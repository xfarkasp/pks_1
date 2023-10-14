#pragma once
#include "ArpFilter.h"

void ArpFilter::findComms() {
    _arpMap = setProtocolMap("Protocols\\arp.txt", true);
    //frames waiting for reply
    std::vector<Frame> replyQue;
    size_t indexOfFound = 0;
    bool delFlag = false;
    for (auto packet : _parent->_frames) {
        std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "ARP") {

            std::stringstream frameBuffer;
            char  hex_string[20];
            for (size_t i = ARP_OPCODE_START; i <= ARP_OPCODE_END; i++) {
                sprintf_s(hex_string, "%.2X", packet.hexFrame.at(i));
                frameBuffer << hex_string;
            }
            packet.arpOpcode = _arpMap[stoi(frameBuffer.str(), 0, 16)];

            for (auto quedFrame : replyQue) {
                if (packet.srcIp == quedFrame.dstIp && packet.dstIp == quedFrame.srcIp) {
                    if (quedFrame.arpOpcode == "REQUEST" && packet.arpOpcode == "REPLY") {
                        std::pair<Frame, Frame> newPair;
                        newPair.first = quedFrame;
                        newPair.second = packet;
                        _commPairs.push_back(newPair);

                        //replyQue.erase(std::next(replyQue.begin(), indexOfFound));
                        delFlag = true;
                        break;
                    }
                    indexOfFound++;
                }
            }
            if (delFlag) {
                replyQue.erase(std::next(replyQue.begin(), indexOfFound));
                indexOfFound = 0;
                delFlag = false;
            }
            else
                replyQue.push_back(packet);
        }
    }
    
    _notCompleteComms = std::move(replyQue);
}

void ArpFilter::serializeArpYaml() {
    findComms();

    size_t comIndex = 0;
    YAML::Emitter output;

    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/24"
        << YAML::Key << "pcap_name"
        << YAML::Value << _parent->_fileName
        << YAML::Key << "filter_name"
        << YAML::Value << "ARP";
    
    auto addComm = [&](std::vector<Frame>comms) {
        output << YAML::BeginMap << YAML::Key << "number_comm" << YAML::Value << comIndex;
        output << YAML::Key << "packets" << YAML::Value << YAML::BeginSeq;
        for (auto packet : comms) {
            std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
            if (frameTypes.size() >= 2 && frameTypes.at(1) == "ARP") {
                output << YAML::BeginMap;
                output << YAML::Key << "frame_number" << YAML::Value << packet.index;
                output << YAML::Key << "len_frame_pcap" << YAML::Value << packet.capLen;
                output << YAML::Key << "len_frame_medium" << YAML::Value << packet.wireLen;
                std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
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

                            output << YAML::Key << "arp_opcode" << YAML::Value << _arpMap[stoi(sBuffer.str(), 0, 16)];
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
                    output << YAML::Key << "protocol" << YAML::Value << _protocolMap[std::stoi(hex_string, 0, 16)];
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
                    sBuffer << std::endl;

                output << YAML::Key << "hexa_frame" << YAML::Value << YAML::Literal << sBuffer.str();
                output << YAML::EndMap;
            }
        }
        output << YAML::EndSeq;
        output << YAML::EndMap;
        
    };

    output << YAML::Key << "complete_comms" << YAML::Value << YAML::BeginSeq;
    while (!_commPairs.empty()) {
        std::vector<Frame>completeConnections;
        std::vector<size_t>removeIndexes;
        Frame commFrame = _commPairs.at(0).first;
        for (size_t i = 0; i < _commPairs.size(); i++) {
            if (_commPairs.at(i).first.dstIp == commFrame.dstIp) {
                completeConnections.push_back(_commPairs.at(i).first);
                completeConnections.push_back(_commPairs.at(i).second);
                removeIndexes.push_back(i);
            }
        }
        comIndex++;
        addComm(completeConnections);
        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (size_t i = 0; i < _commPairs.size(); i++) {
            _commPairs.erase(std::next(_commPairs.begin(), removeIndexes.at(i)));
        }
    }
    output << YAML::EndSeq;

    comIndex = 0;
    output << YAML::Key << "partial_comms" << YAML::Value << YAML::BeginSeq;
    while (!_notCompleteComms.empty()) {
        std::vector<Frame>completeConnections;
        std::vector<size_t>removeIndexes;
        Frame commFrame = _notCompleteComms.at(0);
        for (size_t i = 0; i < _notCompleteComms.size(); i++) {
            if (_notCompleteComms.at(i).dstIp == commFrame.dstIp) {
                completeConnections.push_back(_notCompleteComms.at(i));
                removeIndexes.push_back(i);
            }
        }
        comIndex++;
        addComm(completeConnections);
        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (size_t i = 0; i < removeIndexes.size(); i++) {
            _notCompleteComms.erase(std::next(_notCompleteComms.begin(), removeIndexes.at(i)));
        }
    }
    output << YAML::EndSeq;

    /*while (!_notCompleteComms.empty()) {
        std::vector<Frame>completeConnections;
        std::vector<size_t>removeIndexes;
        Frame commFrame = _notCompleteComms.at(0);
        for (size_t i = 0; i < _notCompleteComms.size(); i++) {
            if (_notCompleteComms.at(i).dstIp == commFrame.dstIp) {
                completeConnections.push_back(_notCompleteComms.at(i));
                removeIndexes.push_back(i);
            }
        }
        comIndex++;
        addComm(completeConnections);
        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (size_t i = 0; i < removeIndexes.size(); i++) {
            _notCompleteComms.erase(std::next(_notCompleteComms.begin(), removeIndexes.at(i)));
        }
    }*/
    

    //addComm(replyQue);



    std::fstream yamlFile;
    yamlFile.open("yaml_output//" + _parent->_fileName.erase(_parent->_fileName.find('.'), _parent->_fileName.size() - 1) + "-ARP.yaml", std::ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _parent->_fileName << std::endl;
}