#pragma once
#include "IcmpFilter.h"
#include <bitset>

void IcmpFilter::findComms() {
    _icmpMap = setProtocolMap("Protocols\\arp.txt", true);
    //frames waiting for reply
    std::vector<Frame> replyQue;
    size_t indexOfFound = 0;
    bool delFlag = false;
    bool lastMfFlag = false; //flag to identify if previous frame was fraged
    for (auto packet : _parent->_frames) {
        std::vector<std::string> frameTypes = _parent->getFrameType(packet.typeSize, packet.hexFrame, packet.isISL);
        if (frameTypes.size() >= 2 && frameTypes.at(1) == "IPv4") {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
            if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "ICMP") {
                sprintf_s(hex_string, "%.2X", packet.hexFrame.at(FRAG_FLAG + packet.ihlOffset));

                //ad frag params to frame struct
                std::bitset<3> fragFlags(std::stoi(hex_string, 0 , 16));
                packet.MF = fragFlags[MF_Flag];
                std::stringstream idBuffer; //buffer to read frag id
                std::stringstream offSetBuffer; //buffer to read frag offset
                /// <summary>
                /// read the frag id and offset from the hexframe
                ///  and ad it to he parameters of the Frame struct
                /// </summary>
                char  hex_string[20];
                for (size_t i = (FRAG_ID_START + packet.ihlOffset); i <= (FRAG_OFFSET_END + packet.ihlOffset); i++) {
                    if ((FRAG_ID_START + packet.ihlOffset) <= i && i <= (FRAG_ID_END + packet.ihlOffset)) {
                        sprintf_s(hex_string, "%.2X", packet.hexFrame[i]);
                        idBuffer << hex_string;
                    }
                }

                sprintf_s(hex_string, "%.2X", packet.hexFrame[FRAG_OFFSET_END]);
                packet.fragID = std::stoi(idBuffer.str(), 0, 16);
                packet.fragOffSet = (std::stoi(hex_string, 0, 16) * 8);
                //if the last frame had true mf flag, ad this frame to frag lis
                if (lastMfFlag == true) {
                    _fragQue.push_back(packet);
                    lastMfFlag = packet.MF;
                    continue;
                }
                lastMfFlag = packet.MF; //set the lastMfFlag to the value of this packets MF to know, if there will be more frags to it

                packet.icmpType = _parent->_icmpMap[packet.hexFrame.at(ICMP_TYPE + packet.ihlOffset)];

                idBuffer.str("");
                idBuffer.clear();

                std::stringstream sqBuffer;
                int identStart;
                int identEnd;

                int seqStart;
                int seqEnd;

                if (packet.icmpType != "TIME EXCEEDED") {
                    identStart = ICMP_IDENT_START;
                    identEnd = ICMP_IDENT_END;
                    
                    seqStart = ICMP_SEQ_START;
                    seqEnd = ICMP_SEQ_END;
                }
                else {
                    identStart = ICMP_IDENT_EXCEEDED_START;
                    identEnd = ICMP_IDENT_EXCEEDED_END;

                    seqStart = ICMP_SEQ_EXCEEDED_START;
                    seqEnd = ICMP_SEQ_EXCEEDED_END;
                }

                for (size_t i = (identStart + packet.ihlOffset); i <= (seqEnd + packet.ihlOffset); i++) {
                    char  hex_string[20];
                    if ((identStart + packet.ihlOffset) <= i && i <= (identEnd + packet.ihlOffset)) {
                        sprintf_s(hex_string, "%.2X", packet.hexFrame[i]);
                        idBuffer << hex_string;
                    }
                    if ((seqStart + packet.ihlOffset) <= i && i <= (seqEnd + packet.ihlOffset)) {
                        sprintf_s(hex_string, "%.2X", packet.hexFrame[i]);
                        sqBuffer << hex_string;
                    }
                }

                packet.icmpID = std::stoi(idBuffer.str(), 0, 16);
                packet.icmpSQ = std::stoi(sqBuffer.str(), 0, 16);

                for (auto quedFrame : replyQue) {
                    if ((packet.srcIp == quedFrame.dstIp || packet.icmpType == "TIME EXCEEDED") &&
                        packet.dstIp == quedFrame.srcIp &&
                        packet.icmpID == quedFrame.icmpID &&
                        packet.icmpSQ == quedFrame.icmpSQ) {

                        std::stringstream quedFrameBuffer;
                        std::stringstream newFrameBuffer;
                        char  hex_string[20];

                        if (quedFrame.icmpType == "ECHO REQUEST" && (packet.icmpType == "ECHO REPLY" || packet.icmpType== "TIME EXCEEDED")) {
                            std::pair<Frame, Frame> newPair;
                            newPair.first = quedFrame;
                            newPair.second = packet;
                            _commPairs.push_back(std::move(newPair));

                            delFlag = true;
                            break;
                        }
                    }
                    indexOfFound++;
                }
                if (delFlag) {
                    replyQue.erase(std::next(replyQue.begin(), indexOfFound));
                    delFlag = false;
                }
                else
                    replyQue.push_back(packet);

                indexOfFound = 0;
            }
        }
    }

    _notCompleteComms = std::move(replyQue);
}
//std::vector<Frame>completeFregments() {
//
//}

void IcmpFilter::serializeIcmpYaml() {
    findComms();

    size_t comIndex = 0;
    YAML::Emitter output;

    output << YAML::BeginMap
        << YAML::Key << "name"
        << YAML::Value << "PKS2023/24"
        << YAML::Key << "pcap_name"
        << YAML::Value << _parent->_fileName
        << YAML::Key << "filter_name"
        << YAML::Value << "ICMP";

    auto addComm = [&](std::vector<Frame>comms, bool complete) {
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
        
        // find the next frame to the fragmented frame
        //iterate through the frames of the comm list
        for (size_t i = 0; i < comms.size(); i++) {
            //if you find a frag with MF set
            if (comms.at(i).MF == true) {
                int delIndex = -1; // index by which we remove it from the fragQue
                int delFlag = false;
                //_fragQue iterator
                for (auto frag : _fragQue) {
                    delIndex++; //increment dell index after every 
                    //match src/dst ip, frag ids
                    if (comms.at(i).fragID == frag.fragID &&
                        comms.at(i).srcIp == frag.srcIp &&
                        comms.at(i).dstIp == frag.dstIp) {
                        comms.insert(comms.begin() + (i + 1), frag);
                        delFlag = true; // set delete flag to true
                        //if this was the last frag, break for
                        if (frag.MF == false) 
                            break;
                    }
                    //if frag was matched from _fragQue, delete it by its index from 
                    if (delFlag) {
                        _fragQue.erase(std::next(_fragQue.begin(), delIndex));
                        delFlag = false;
                    }
                }
            }
        }

        int previousFragId = -1;
        for (auto packet : comms) {
            char  hex_string[20];
            sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));

            if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "ICMP") {
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
                    if (packet.MF || packet.fragID == previousFragId) {
                        output << YAML::Key << "id" << YAML::Value << packet.fragID;
                        output << YAML::Key << "flags_mf" << YAML::Value << packet.MF;
                        output << YAML::Key << "frag_offset" << YAML::Value << packet.fragOffSet;
                        previousFragId = packet.fragID;
                    }
                    else {
                        char  hex_string[20];
                        sprintf_s(hex_string, "%.2X", packet.hexFrame.at(23));
                        output << YAML::Key << "protocol" << YAML::Value << _parent->_protocolMap[std::stoi(hex_string, 0, 16)];
                        if (_parent->_protocolMap[std::stoi(hex_string, 0, 16)] == "ICMP") {
                            output << YAML::Key << "icmp_type" << YAML::Value << packet.icmpType;
                            if (complete)
                                output << YAML::Key << "icmp_id" << YAML::Value << packet.icmpID;
                            if (complete)
                                output << YAML::Key << "icmp_seq" << YAML::Value << packet.icmpSQ;
                        }
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
        addComm(completeConnections, true);
        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (size_t i = 0; i < removeIndexes.size(); i++) {
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
        addComm(completeConnections, false);
        std::reverse(removeIndexes.begin(), removeIndexes.end());
        for (size_t i = 0; i < removeIndexes.size(); i++) {
            _notCompleteComms.erase(std::next(_notCompleteComms.begin(), removeIndexes.at(i)));
        }
    }
    output << YAML::EndSeq;

    std::fstream yamlFile;
    yamlFile.open("yaml_output//ICMP//" + _parent->_fileName.erase(_parent->_fileName.find('.'), _parent->_fileName.size() - 1) + "-ICMP.yaml", std::ios_base::out);
    if (yamlFile.is_open())
    {
        yamlFile << output.c_str();
        yamlFile.close();
    }
    std::cout << "succesfuly serialized pcap " + _parent->_fileName << std::endl;
}