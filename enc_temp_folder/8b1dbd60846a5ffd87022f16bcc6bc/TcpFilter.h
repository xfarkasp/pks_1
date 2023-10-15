#pragma once
#include "PcapParser.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>

class TcpFilter : public PcapParser {
public:
	TcpFilter(PcapParser* parent) { _parent = parent; }
	void findComms();
	void serializeTcpYaml();
public:
	PcapParser* _parent;
	std::map<unsigned int, std::string> _tftpOptMap;
	std::vector<std::vector<Frame>> _completeComms;
	std::vector<std::vector<Frame>> _notCompleteComms;
};
