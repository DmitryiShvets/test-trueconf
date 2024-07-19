CXX = g++
CXXFLAGS = -Wall -Wextra -pedantic
LIBS = -lpcap

all: tcp_count

tcp_count: src/main.cpp
	$(CXX) $(CXXFLAGS) -o tcp_count src/main.cpp $(LIBS)

clean: rm -f tcp_count