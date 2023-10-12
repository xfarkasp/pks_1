#pragma once
#include <iostream>
#include "PcapParser.h"

int main(int argc, char* argv[])
{
    /*std::string file;
    if (argc == 1) {
        std::cout << "Enter pcap file name: ";
        std::cin >> file;
    }
    else if (argc > 1)
        file = argv[1];*/
    
    PcapParser *parser = new PcapParser();
    parser->parseFrame("C:\\Users\\lordp\\OneDrive\\Documents\\AkademickaPoda\\2.Rok\\3.ZS\\MIKO2.0\\test_pcap_files\\vzorky_pcap_na_analyzu\\trace-27.pcap");
    parser->serializeYaml();
}