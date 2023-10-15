#pragma once
#include "TcpFilter.h"
#include <bitset>

void TcpFilter::findComms() {
    //frames waiting for reply
    std::vector<Frame> tcpComStartQue;
    std::vector<Frame> tcpFrameQue;
    size_t indexOfFound = 0;
    bool delFlag = false;
    for (auto packet : _parent->_frames) {
        std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "IPv4") {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
            if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "TCP") {
                std::string portName = "";
                if (_parent->_portMap.find(packet.dstPort) != _parent->_portMap.end())
                    portName = _parent->_portMap[packet.dstPort];

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

    for (auto packet : tcpComStartQue) {
        std::vector<unsigned int> removeIndexes;
        std::vector<Frame> newComm;

        unsigned int rmIndex = 0;

        bool isComplete = false;
        bool synAckFound = false;
        bool ackFound = false;

        bool finFirst = false;
        bool finSecond = false;
        bool finAckLast = false;
        //when connection opens in connection
        bool newConOpendDuringThisone = false;
        bool newFinFirst = false;
        bool newAckFirst = false;
        bool newFinSecond = false;
        bool newAckSecond = false;

        //add comm starter tcp frame
        newComm.push_back(packet);
        for (auto tcpFrame : tcpFrameQue) {
            if (tcpFrame.index == 68 && packet.index == 61)
                int mojeVajcia = 0;
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
                    //if a new connection opens during this one
                    //if (newConOpendDuringThisone || tcpFrame.tcpFlags[TCP_SYN]) {
                    //    newConOpendDuringThisone = true;
                    //    //if newly opened connection is terminated by rst-ack flags
                    //    if(tcpFrame.tcpFlags[TCP_RST] && tcpFrame.tcpFlags[TCP_ACK])
                    //        newConOpendDuringThisone = false;
                    //    //if suffering is neccesery
                    //    else if (!newFinFirst && tcpFrame.tcpFlags[TCP_FIN] && tcpFrame.tcpFlags[TCP_ACK]) {
                    //        newFinFirst = true;
                    //    }
                    //    else if (!newAckFirst && newFinFirst && tcpFrame.tcpFlags[TCP_ACK]) {
                    //        newAckFirst = true;
                    //    }
                    //    else if (!newFinSecond  && newAckFirst && newFinFirst && tcpFrame.tcpFlags[TCP_FIN] && tcpFrame.tcpFlags[TCP_ACK]) {
                    //        newFinSecond = true;
                    //    }
                    //    else if (newFinSecond && tcpFrame.tcpFlags[TCP_ACK]) {
                    //        newConOpendDuringThisone = false;
                    //        newFinFirst = false;
                    //        newAckFirst = false;
                    //        newFinSecond = false;
                    //        newAckSecond = false;
                    //    }
                    //    rmIndex++;
                    //    continue;
                    //}
                    newComm.push_back(tcpFrame);
                    removeIndexes.push_back(rmIndex);
                    //conection ended with RST ACK
                    //if (tcpFrame.tcpFlags[TCP_RST] && tcpFrame.tcpFlags[TCP_ACK]) {
                    //    isComplete = true;
                    //    break;
                    //}
                    ////if first fin-ack found
                    //else if (!finFirst && tcpFrame.tcpFlags[TCP_FIN] && tcpFrame.tcpFlags[TCP_ACK]) {
                    //    finFirst = true;
                    //}
                    //else if (!finAckLast && finFirst && tcpFrame.tcpFlags[TCP_ACK]) {
                    //    finAckLast = true;
                    //}
                    //else if (!finSecond && finAckLast && tcpFrame.tcpFlags[TCP_FIN] && tcpFrame.tcpFlags[TCP_ACK]) {
                    //    finSecond = true;
                    //}
                    //else if (finSecond && tcpFrame.tcpFlags[TCP_ACK]) {
                    //    isComplete = true;
                    //    break;
                    //}
                }
            }
            rmIndex++;
        }
        if (isComplete)
            _completeComms.push_back(newComm);
        else
            _notCompleteComms.push_back(newComm);

        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (unsigned int rmI : removeIndexes)
            tcpFrameQue.erase(std::next(tcpFrameQue.begin(), rmI));

    }
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
                    if (packet.tftpBlockCount != SIZE_MAX)
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

    output << YAML::Key << "complete_comms" << YAML::Value << YAML::BeginSeq;
    //for (auto comm : _completeComms) {
    //    comIndex++;
    //    addComm(comm.frames);
    //}
    output << YAML::EndSeq;

    comIndex = 0;
    output << YAML::Key << "partial_comms" << YAML::Value << YAML::BeginSeq;
    //for (auto comm : _notCompleteComms) {
    //    comIndex++;
    //    addComm(comm.frames);
    //}
    output << YAML::EndSeq;

    std::fstream yamlFile;
    yamlFile.open("yaml_output//" + _parent->_fileName.erase(_parent->_fileName.find('.'), _parent->_fileName.size() - 1) + "-TFTP.yaml", std::ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _parent->_fileName << std::endl;
}