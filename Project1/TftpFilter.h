#pragma once
#include "PcapParser.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>

struct TFTPCOMM {
	size_t index;
	std::string typeName;
	unsigned int fileSize;
	unsigned int blockSize = INT_MAX;
	std::vector<Frame> frames;
};

class TftpFilter : public PcapParser {
public:
	TftpFilter(PcapParser* parent) { _parent = parent; }
	void findComms();
	void serializeTftpYaml();
public:
	PcapParser* _parent;
	std::map<unsigned int, std::string> _tftpOptMap;
	std::vector<TFTPCOMM> _completeComms;
	std::vector<TFTPCOMM> _notCompleteComms;
};