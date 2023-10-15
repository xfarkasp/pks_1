#pragma once
#include <iostream>
#include "PcapParser.h"
#include <chrono>
#include <ctime>

int main(int argc, char* argv[])
{
    /*std::string file;
    if (argc == 1) {
        std::cout << "Enter pcap file name: ";
        std::cin >> file;
    }
    else if (argc > 1)
        file = argv[1];*/
    std::chrono::time_point<std::chrono::system_clock> m_StartTime = std::chrono::system_clock::now();;
    
    PcapParser *parser = new PcapParser();
    parser->parseFrame("C:\\Users\\pedro\\Documents\\PKS\\vzorky_pcap_na_analyzu\\trace-8.pcap");
    //parser->serializeYaml();
    //parser->icmpFilter();
    //parser->tftpFilter();
    parser->tcpFilter();

    std::chrono::time_point<std::chrono::system_clock> endTime = std::chrono::system_clock::now();

    std::cout << "Parsing time: " << (std::chrono::duration_cast<std::chrono::milliseconds>(endTime - m_StartTime).count()) << " mili seconds";
}