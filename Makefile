PCAP_INCLUDE=/usr/include/pcap
INCLUDE=./header
SRC=./src

DEBUG=-g

PROJECT_HEADERS := $(INCLUDE)/common.h
PROJECT_HEADERS := $(INCLUDE)/Map.h
PROJECT_HEADERS := $(INCLUDE)/PcapAnalyzer.h

all: main.o PcapAnalyzer.o  
	g++ $(DEBUG) -o ip-stat $^ -lpcap

main.o: $(SRC)/main.cc $(PROJECT_HEADERS)
	g++ $(DEBUG) -c $< -lpcap -I$(PCAP_INCLUDE) -I$(INCLUDE)

PcapAnalyzer.o: $(SRC)/PcapAnalyzer.cc $(PROJECT_HEADERS)
	g++ $(DEBUG) -c $< -I$(PCAP_INCLUDE) -I$(INCLUDE)

clean:
	rm -f *.o ip-stat