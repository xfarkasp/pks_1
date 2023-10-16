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
	TcpFilter(PcapParser* parent, std::string filterName) {
		_parent = parent; 
		_filterName = filterName;
	}
	void findComms();
	void serializeTcpYaml();
	void validateComm(std::vector<Frame> comm);
public:
	PcapParser* _parent;
	std::string _filterName;
	std::map<unsigned int, std::string> _tftpOptMap;
	std::vector<std::vector<Frame>> _completeComms;
	std::vector<std::vector<Frame>> _notCompleteComms;
};
