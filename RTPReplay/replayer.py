import sys
import socket, time
 
UDP_IP = "127.0.0.1"
UDP_PORT = 5004

sock = socket.socket(socket.AF_INET,
                      socket.SOCK_DGRAM)

f = open(sys.argv[1], 'rb')

dump = f.read()



ind = dump.find(b"\n")
header = dump[0:ind]

print(header)

ind = ind + 4*4 + 1

while ind < len(dump):
	ind +=2
	plen = (dump[ind] << 8) + dump[ind+1]
	ind += 6
	packet = dump[ind:ind+plen]
	print(packet)
	sock.sendto(packet, (UDP_IP, UDP_PORT))
	ind = ind + plen
	time.sleep(.1)
