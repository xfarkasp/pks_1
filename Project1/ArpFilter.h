#pragma once
#include "PcapParser.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>

class ArpFilter : public PcapParser {
	public:
		ArpFilter(PcapParser* parent) {_parent = parent;}
		void findComms();
		void serializeArpYaml();
	public:
		PcapParser* _parent;
		std::map<unsigned int, std::string> _arpMap;
		std::vector<std::pair<Frame, Frame>> _commPairs;
		std::vector<Frame> _notCompleteComms;

};