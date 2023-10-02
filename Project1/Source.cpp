#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include <pcap.h>
#include <yaml-cpp/yaml.h>
#include "PcapParser.h"
#include <sstream>

using namespace std;

int main(int argc, char* argv[])
{
    string file;
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