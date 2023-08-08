CC = g++
CFLAGS = -std=c++11 #-Wall -Wextra
LDFLAGS = -fno-pie

LDLIBS = -lpcap

VPATH = inc src

SOURCES := $(wildcard src/*.cpp)
HEADERS := $(wildcard inc/*.h)
OBJS := $(SOURCES:.cpp=.o)

TARGET = arp-spoof

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
#	$(CC) -o $@ $(OBJS) $(LDLIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $< -Iinc
#	$(CC) $(CFLAGS) -c -o $@ $< -Iinc

clean:
	rm -f $(TARGET) $(OBJS) $(TARGET).exe

