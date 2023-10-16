#pragma once
#include <iostream>
#include "PcapParser.h"
#include <chrono>
#include <ctime>

int main(int argc, char* argv[])
{
    std::string file = "";
    std::string parameter = "";
    std::string filterName = "";
    if (argc == 2) {
        file = argv[1];
    }
    else if (argc == 4){
        parameter = argv[1];
        filterName = argv[2];
        file = argv[3];
    }
        
    std::chrono::time_point<std::chrono::system_clock> m_StartTime = std::chrono::system_clock::now();;
    PcapParser *parser = new PcapParser();
    parser->parseFrame(file);
    if (parameter == "-p") {
        if (filterName == "HTTP")
            parser->tcpFilter("HTTP");
        else if (filterName == "HTTPS")
            parser->tcpFilter("HTTPS");
        else if (filterName == "TELNET")
            parser->tcpFilter("TELNET");
        else if (filterName == "SSH")
            parser->tcpFilter("SSH");
        else if (filterName == "FTP_CONTROLL")
            parser->tcpFilter("FTP_CONTROLL");
        else if (filterName == "FTP_DATA")
            parser->tcpFilter("FTP_DATA");
        else if (filterName == "TFTP")
            parser->tftpFilter();
        else if (filterName == "ICMP")
            parser->icmpFilter();
        else if (filterName == "ARP")
            parser->arpFilter();
        else
            std::cout << "wrong parameter input, try command aggain." << std::endl;
    }
    else
        parser->serializeYaml();

    std::chrono::time_point<std::chrono::system_clock> endTime = std::chrono::system_clock::now();
    std::cout << "Parsing time: " << (std::chrono::duration_cast<std::chrono::milliseconds>(endTime - m_StartTime).count()) << " mili seconds";
}