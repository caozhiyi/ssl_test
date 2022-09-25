SRCS = $(wildcard ./*.cpp)

OBJS = $(patsubst %.cpp, %.o, $(SRCS))

CC = g++

INCLUDES = -I../              \
           -I../third/        \

#debug
CCFLAGS = -fPIC -m64 -g -std=c++11 -lstdc++ -pipe  -lpthread -fpermissive

GTESTLIB = ../third/lib/libgtest.a
CRYPTOLIB = ../third/lib/libcrypto.a
SSLLIB = ../third/lib/libssl.a

BIN = ssl-test

all:$(BIN)

$(BIN):$(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(CCFLAGS) $(INCLUDES) $(GTESTLIB) ${SSLLIB} ${CRYPTOLIB}

%.o : %.cpp
	$(CC) -c $< -o $@ $(CCFLAGS) $(INCLUDES) 

clean:
	rm -rf $(BIN) $(OBJS) *.log

test:
	./$(BIN)