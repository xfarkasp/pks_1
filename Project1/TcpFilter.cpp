#pragma once
#include "TcpFilter.h"
#include <bitset>

void TcpFilter::findComms() {
    //frames waiting for reply
    std::vector<Frame> tcpComStartQue;
    std::vector<Frame> tcpFrameQue;
    std::vector<std::vector<Frame>> tcpComms;
    size_t indexOfFound = 0;
    bool delFlag = false;
    for (auto packet : _parent->_frames) {
        std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "IPv4") {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
            if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "TCP") {
                std::string portNameSrc = "";
                std::string portNameDst = "";
                if (_parent->_portMap.find(packet.srcPort) != _parent->_portMap.end())
                    portNameSrc = _parent->_portMap[packet.srcPort];
                if (_parent->_portMap.find(packet.dstPort) != _parent->_portMap.end())
                    portNameDst = _parent->_portMap[packet.dstPort];

                if (portNameSrc == _filterName || portNameDst == _filterName) {
                    std::stringstream tcpFlagsBuffer; //buffer to read flags
                    char  hex_string[20];
                    sprintf_s(hex_string, "%.2X", packet.hexFrame[(TCP_FLAGS_END + packet.ihlOffset)]);
                    std::bitset<8> fragFlags(std::stoi(hex_string, 0, 16));
                    packet.tcpFlags = fragFlags;
                    if (fragFlags[TCP_SYN] && !fragFlags[TCP_ACK])
                        tcpComStartQue.push_back(packet);
                    else
                        tcpFrameQue.push_back(packet);
                }
            }
        }
    }

    for (auto packet : tcpComStartQue) {
        std::vector<unsigned int> removeIndexes;
        std::vector<Frame> newComm;

        unsigned int rmIndex = 0;

        bool isComplete = false;
        bool synAckFound = false;
        bool ackFound = false;

        //add comm starter tcp frame
        newComm.push_back(packet);
        for (auto tcpFrame : tcpFrameQue) {
            if (((packet.dstIp == tcpFrame.srcIp && packet.srcIp == tcpFrame.dstIp) ||
                (packet.dstIp == tcpFrame.dstIp && packet.srcIp == tcpFrame.srcIp)) &&
                ((packet.dstPort == tcpFrame.srcPort && packet.srcPort == tcpFrame.dstPort) ||
                (packet.dstPort == tcpFrame.dstPort && packet.srcPort == tcpFrame.srcPort))) {
                    
                //find ack frame after syn-ack
                if (!synAckFound && tcpFrame.tcpFlags[TCP_SYN] && tcpFrame.tcpFlags[TCP_ACK]) {
                    synAckFound = true;
                    newComm.push_back(tcpFrame);
                    removeIndexes.push_back(rmIndex);
                    rmIndex++;
                    continue;
                }
                //find first ack frame after syn-ack
                if (!ackFound && synAckFound && !tcpFrame.tcpFlags[TCP_SYN] && tcpFrame.tcpFlags[TCP_ACK]) {
                    ackFound = true;
                    newComm.push_back(tcpFrame);
                    removeIndexes.push_back(rmIndex);
                    rmIndex++;
                    continue;
                }

                if (ackFound) {
                    newComm.push_back(tcpFrame);
                    removeIndexes.push_back(rmIndex);
                }
            }
            rmIndex++;
        }
        validateComm(newComm);

        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (unsigned int rmI : removeIndexes)
            tcpFrameQue.erase(std::next(tcpFrameQue.begin(), rmI));
    }
    std::cout << "";
}

void TcpFilter::validateComm(std::vector<Frame> comm) {
    bool validStart = false;
    bool validEnd = false;

    //validate connection establishment
    ///check if connection began correctly with 3 way hs
    if (comm.size() > 2 && (comm.at(0).tcpFlags[TCP_SYN] && !comm.at(0).tcpFlags[TCP_ACK] &&
        comm.at(1).tcpFlags[TCP_SYN] && comm.at(1).tcpFlags[TCP_ACK] &&
        !comm.at(2).tcpFlags[TCP_SYN] && comm.at(2).tcpFlags[TCP_ACK]))
        validStart = true;
    ///check if connection began correctly with 4 way hs
    else if (comm.size() > 3 && (comm.at(0).tcpFlags[TCP_SYN] && !comm.at(0).tcpFlags[TCP_ACK] &&
             comm.at(1).tcpFlags[TCP_SYN] && !comm.at(1).tcpFlags[TCP_ACK] &&
             !comm.at(2).tcpFlags[TCP_SYN] && comm.at(2).tcpFlags[TCP_ACK] &&
             !comm.at(3).tcpFlags[TCP_SYN] && comm.at(3).tcpFlags[TCP_ACK]))
        validStart = true;

    //validate connection ending
    //reverse the vector to analyze connection ending
    std::reverse(comm.begin(), comm.end());

    //check if connection was terminated with [RST,ACK]
    if (comm.at(0).tcpFlags[TCP_RST])
        validEnd = true;
    //check if connection was terminated with [FIN,ACK] -> [ACK] -> [FIN,ACK] -> [ACK] (normal 4 way hs)
    else if (comm.size() > 3 && (comm.at(0).tcpFlags[TCP_ACK] && !comm.at(0).tcpFlags[TCP_FIN] &&
        comm.at(1).tcpFlags[TCP_ACK] && comm.at(1).tcpFlags[TCP_FIN] &&
        comm.at(2).tcpFlags[TCP_ACK] && !comm.at(2).tcpFlags[TCP_FIN] &&
        comm.at(3).tcpFlags[TCP_ACK] && comm.at(3).tcpFlags[TCP_FIN]))
        validEnd = true;
    //check if connection was terminated with [FIN,ACK] -> [ACK] synchronized TCP connection termination 1
    else if (comm.size() > 2 && (comm.at(1).tcpFlags[TCP_ACK] && comm.at(1).tcpFlags[TCP_FIN] &&
        comm.at(2).tcpFlags[TCP_ACK] || comm.at(2).tcpFlags[TCP_FIN]))
        validEnd = true;
    //check if connection was terminated with [FIN,ACK] -> [FIN,ACK] -> [ACK] ->  [ACK] synchronized TCP connection termination 2
    else if (comm.size() > 3 && (comm.at(0).tcpFlags[TCP_ACK] && !comm.at(0).tcpFlags[TCP_FIN] &&
        comm.at(1).tcpFlags[TCP_ACK] && !comm.at(1).tcpFlags[TCP_FIN] &&
        comm.at(2).tcpFlags[TCP_ACK] && comm.at(2).tcpFlags[TCP_FIN] &&
        comm.at(3).tcpFlags[TCP_ACK] && comm.at(3).tcpFlags[TCP_FIN]))
        validEnd = true;
    //reverse the vectors back before adding
    std::reverse(comm.begin(), comm.end());
    if (validStart && validEnd)
        _completeComms.push_back(comm);
    else
        _notCompleteComms.push_back(comm);
}

void TcpFilter::serializeTcpYaml() {
    findComms();
    size_t comIndex = 0;
    YAML::Emitter output;

    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/24"
        << YAML::Key << "pcap_name"
        << YAML::Value << _parent->_fileName
        << YAML::Key << "filter_name"
        << YAML::Value << _filterName;
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
                if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "TCP") {
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
            addComm(comm);
        }
        output << YAML::EndSeq;
    }
    else
        output << YAML::Key << "complete_comms" << YAML::Value << YAML::BeginSeq << YAML::EndSeq;;

    if (!_notCompleteComms.empty()) {
        comIndex = 0;
        output << YAML::Key << "partial_comms" << YAML::Value << YAML::BeginSeq;
        if (!_notCompleteComms.empty())
            addComm(_notCompleteComms.at(0));
        output << YAML::EndSeq;
    }
    else
        output  << YAML::Key << "partial_comms" << YAML::Value << YAML::BeginSeq << YAML::EndSeq;;
    
    output << YAML::EndMap;
    std::fstream yamlFile;
    yamlFile.open("yaml_output//" + _filterName + "//" + _parent->_fileName.erase(_parent->_fileName.find('.'), _parent->_fileName.size() - 1) + "-" + _filterName + ".yaml", std::ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _parent->_fileName << std::endl;
}