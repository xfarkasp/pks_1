#pragma once
#include "TftpFilter.h"
#include <bitset>

void TftpFilter::findComms() {

    _tftpOptMap = setProtocolMap("Protocols\\tftp.txt", true);

    //frames waiting for reply
    std::vector<Frame> tftpStartQue;
    std::vector<Frame> tftpQue;
    size_t indexOfFound = 0;
    bool delFlag = false;

    for (auto packet : _parent->_frames) {
        std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "IPv4") {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
            if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "UDP") {
                std::string portName = "";
                if (_parent->_portMap.find(packet.dstPort) != _parent->_portMap.end())
                    portName = _parent->_portMap[packet.dstPort];

                    std::stringstream udpPayloadSize; 
                    char  hex_string[20];
                    for (size_t i = (UDP_PAYLOAD_SIZE_START + packet.ihlOffset); i <= (UDP_PAYLOAD_SIZE_END + packet.ihlOffset); i++) {
                        if ((UDP_PAYLOAD_SIZE_START + packet.ihlOffset) <= i && i <= (UDP_PAYLOAD_SIZE_END + packet.ihlOffset)) {
                            sprintf_s(hex_string, "%.2X", packet.hexFrame[i]);
                            udpPayloadSize << hex_string;
                        }
                    }
                    packet.udpPayload = std::stoi(udpPayloadSize.str(), 0, 16);
                    sprintf_s(hex_string, "%.2X", packet.hexFrame.at(TFTP_OPCODE));
                    packet.tftpOptcode = _tftpOptMap[std::stoi(hex_string, 0, 16)];
                    if(portName != "TFTP")
                        tftpQue.push_back(packet);
                    else
                        tftpStartQue.push_back(packet);
            }
        }
    }

    for (auto packet : tftpStartQue) {
        std::vector<unsigned int> removeIndexes;
        unsigned int rmIndex = 0;
        TFTPCOMM newComm;
        bool isComplete = false;
        newComm.frames.push_back(packet);
        size_t blockNum = 0;
        for (auto tftpFrame : tftpQue) {
            if ((packet.dstIp == tftpFrame.srcIp && packet.srcIp == tftpFrame.dstIp) ||
                (packet.dstIp == tftpFrame.dstIp && packet.srcIp == tftpFrame.srcIp)) {
                if (isComplete && tftpFrame.tftpOptcode == "Acknowledgement") {
                    tftpFrame.tftpBlockCount = blockNum;
                    removeIndexes.push_back(rmIndex);
                    newComm.frames.push_back(tftpFrame);
                    break;
                }
                else if (!isComplete && (tftpFrame.tftpOptcode == "Acknowledgement" || tftpFrame.tftpOptcode == "Data" || tftpFrame.tftpOptcode == "Error")) {
                    
                    if (tftpFrame.tftpOptcode == "Data") {

                        if (newComm.blockSize == INT_MAX)
                            newComm.blockSize = tftpFrame.udpPayload;

                        tftpFrame.tftpBlockCount = ++blockNum;
                    }
                    else if(tftpFrame.tftpOptcode == "Acknowledgement")
                        tftpFrame.tftpBlockCount = blockNum;

                    newComm.frames.push_back(tftpFrame);
                    removeIndexes.push_back(rmIndex);

                    if (tftpFrame.tftpOptcode == "Data" && (tftpFrame.udpPayload < newComm.blockSize || tftpFrame.udpPayload < TFTP_DEFAULT_SIZE)){
                        isComplete = true;
                    }
                    
                    if (tftpFrame.tftpOptcode == "Error") {
                        isComplete = true;
                        break;
                    }
                }
            }
            rmIndex++;
            if (&tftpFrame == &tftpQue.back()) {
                isComplete = false;
            }

        }
        if (isComplete)
            _completeComms.push_back(newComm);
        else
            _notCompleteComms.push_back(newComm);
        
        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for(unsigned int rmI : removeIndexes)
            tftpQue.erase(std::next(tftpQue.begin(), rmI));
        
    }
}

void TftpFilter::serializeTftpYaml() {
    findComms();
    size_t comIndex = 0;
    YAML::Emitter output;

    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/24"
        << YAML::Key << "pcap_name"
        << YAML::Value << _parent->_fileName
        << YAML::Key << "filter_name"
        << YAML::Value << "TFTP";

    auto addComm = [&](std::vector<Frame>comms) {
        output << YAML::BeginMap << YAML::Key << "number_com" << YAML::Value << comIndex;
        std::stringstream sBuffer;
        for (auto byte : comms.at(0).srcIp) {
            sBuffer << byte << ".";
        }
        output << YAML::Key << "src_comm" << sBuffer.str().erase(sBuffer.str().size() - 1);
        sBuffer.str("");
        sBuffer.clear();
        for (auto byte : comms.at(0).dstIp) {
            sBuffer << byte << ".";
        }
        output << YAML::Key << "dst_comm" << YAML::Value << sBuffer.str().erase(sBuffer.str().size() - 1);
        sBuffer.str("");
        sBuffer.clear();
        output << YAML::Key << "packets" << YAML::Value << YAML::BeginSeq;

        int previousFragId = -1;
        for (auto packet : comms) {
            char  hex_string[20];

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
                output << YAML::Key << "protocol" << YAML::Value << _parent->_protocolMap[std::stoi(hex_string, 0, 16)];
                if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "UDP") {
                    output << YAML::Key << "src_port" << YAML::Value << packet.srcPort;
                    output << YAML::Key << "dst_port" << YAML::Value << packet.dstPort;

                    bool srcKnown = (_parent->_portMap.find(packet.srcPort) != _parent->_portMap.end());
                    bool dstKnown = (_parent->_portMap.find(packet.dstPort) != _parent->_portMap.end());
                    if (srcKnown && dstKnown)
                        output << YAML::Key << "app_protocol" << YAML::Value << _parent->_portMap[packet.srcPort] + ", " + _parent->_portMap[packet.dstPort];
                    else if (srcKnown)
                        output << YAML::Key << "app_protocol" << YAML::Value << _parent->_portMap[packet.srcPort];
                    else if (dstKnown)
                        output << YAML::Key << "app_protocol" << YAML::Value << _parent->_portMap[packet.dstPort];

                    output << YAML::Key << "tftp_opcode" << YAML::Value << packet.tftpOptcode;
                    if(packet.tftpBlockCount != SIZE_MAX)
                        output << YAML::Key << "tftp_block" << YAML::Value << packet.tftpBlockCount;
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
    
        output << YAML::EndSeq;
        output << YAML::EndMap;
    };
    if (!_completeComms.empty()) {
        output << YAML::Key << "complete_comms" << YAML::Value << YAML::BeginSeq;
        for (auto comm : _completeComms) {
            comIndex++;
            addComm(comm.frames);
        }
        output << YAML::EndSeq;
    }

    if (!_notCompleteComms.empty()) {
        comIndex = 0;
        output << YAML::Key << "partial_comms" << YAML::Value << YAML::BeginSeq;
        for (auto comm : _notCompleteComms) {
            comIndex++;
            addComm(comm.frames);
        }
        output << YAML::EndSeq;
    }

    std::fstream yamlFile;
    yamlFile.open("yaml_output//TFTP//" + _parent->_fileName.erase(_parent->_fileName.find('.'), _parent->_fileName.size() - 1) + "-TFTP.yaml", std::ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _parent->_fileName << std::endl;
}