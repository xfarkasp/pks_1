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
    /*std::stringstream test("this_is_a_test_string");
    std::string segment;
    std::vector<std::string> seglist;

    while (std::getline(test, segment, '_'))
    {
        seglist.push_back(segment);
    }

    std::map<int, std::string> mapa;
    mapa.insert({ 2, "a"});
    mapa.insert({ 6, "b"});
    mapa.insert({ 3, "20" });
    mapa.insert({ 4, "50" });

    cout << mapa[2];*/
    string file = "C:\\Users\\lordp\\OneDrive\\Documents\\AkademickaPoda\\2.Rok\\3.ZS\\MIKO 2.0\\test_pcap_files\\vzorky_pcap_na_analyzu\\trace-27.pcap";
    
    PcapParser *parser = new PcapParser();
    parser->parseFrame(file);
    parser->serializeYaml();
}