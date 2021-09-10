import sys
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
import time
def packetgen():



  invalid_IP = [10,127,254,255,1,2,169,172,192]

  first_IP = randrange(1,256)


  while first_IP in Invalid_IP:
    first_address = randrange(1,256)
    print first_address
  ip_addr = ".".join([str(first),str(randrange(1,256)), str(randrange(1,256)),str(randrange(1,256))]) #used to aggregate IP's together with numbers from different OCtet.
  print ip_addr
  return ip_addr


def main(): #the main function can be utilised to a mere 6 times in a same instance with 10 seconds of sleep in between.
  for i in range (1,6):
    mymain()
    time.sleep (10)

def mymain():

 
  dstIP = sys.argv[1:]
  print dstIP



  interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

  for i in xrange(0,500):

    packets = Ether()/IP(dst=dstIP,src=packetgen())/UDP(dport=50001,sport=50002) #grpc port opened by p4runtime
    print(repr(packets))


    sendp( packets,iface=interface.rstrip(),inter=0.025)




if __name__=="__main__":
  main()