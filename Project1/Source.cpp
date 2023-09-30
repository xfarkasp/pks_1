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
    string file = "C:\\Users\\lordp\\OneDrive\\Documents\\AkademickaPoda\\2.Rok\\3.ZS\\MIKO 2.0\\test_pcap_files\\vzorky_pcap_na_analyzu\\eth-1.pcap";
    
    PcapParser *parser = new PcapParser();
    parser->parseFrame(file);
    parser->serializeYaml();
}