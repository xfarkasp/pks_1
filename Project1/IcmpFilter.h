#pragma once
#include "PcapParser.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>

class IcmpFilter : public PcapParser {
public:
	IcmpFilter(PcapParser* parent) { _parent = parent; }
	void findComms();
	void serializeIcmpYaml();
public:
	PcapParser* _parent;
	std::map<unsigned int, std::string> _icmpMap;
	std::vector<std::pair<Frame, Frame>> _commPairs;
	std::vector<Frame> _notCompleteComms;
	std::vector<Frame> _fragQue;

};