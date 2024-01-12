LDLIBS += -lpcap

all: airodump

airodump: *.c

clean:
	rm -f airodump *.o
