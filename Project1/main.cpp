#pragma once
#include <iostream>
#include "PcapParser.h"

int main(int argc, char* argv[])
{
    std::string file;
    if (argc == 1) {
        std::cout << "Enter pcap file name: ";
        std::cin >> file;
    }
    else if (argc > 1)
        file = argv[1];
    
    PcapParser *parser = new PcapParser();
    parser->parseFrame(file);
    parser->serializeYaml();
}