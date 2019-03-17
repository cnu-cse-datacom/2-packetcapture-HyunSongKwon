import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header=struct.unpack("!6c6c2s",data)
    ether_dest = convert_ethernet_address(ethernet_header[0:6])
    ether_src = convert_ethernet_address(ethernet_header[6:12])
    ip_header="0x"+ethernet_header[12].hex()

    print("=========ethernet header==========")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:",ether_dest)
    print("ip_version",ip_header)

def convert_ethernet_address(data):
    ethernet_addr =list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr=":".join(ethernet_addr)
    return ethernet_addr


def parsing_ip_header(data):
    ip_header=struct.unpack("!1c1c2s2s2s1c1c2s4c4c",data)
    
    print("============ip header=============")
    
    ip_ver_len= int(ip_header[0].hex(), 16)
    print("ip_version:",ip_ver_len // 16)
    print("ip_length:", ip_ver_len % 16)

    differ_expli=int(ip_header[1].hex(),16)
    print("differentiated_service_codepoint:",differ_expli//16)
    print("explicit_congestion_notification:",differ_expli%16)

    total_length=int(ip_header[2].hex(),16)
    print("total_length:",total_length)
    
    identification=ip_header[3].hex()
    print("identification:0x",identification)

    flags=ip_header[4].hex()
    print("flags:0x",flags)
    flags_int=int(ip_header[4].hex(),16)
    print(">>>reserved_bit:",(flags_int>>15)&0x0001)
    print(">>>fragments:",(flags_int>>13)& 0x0006)
    print(">>>fragments_offset:",flags_int & 0x1fff)


    time_to_live=int(ip_header[5].hex(),16)
    print("Time to live:",time_to_live)

    protocol=ip_header[6].hex()
    print("protocol:0x",protocol)

    header_check=ip_header[7].hex()
    print("header checksum:0x",header_check)

    source_addr=convert_ip_address(ip_header[8:12])
    print("source_ip_address:",source_addr)

    dest_addr=convert_ip_address(ip_header[12:16])
    print("dest_ip_address:",dest_addr)

def ch_UDP_TCP(data):
    temp=struct.unpack("1c",data)
    result=int(temp[0].hex(),16)
    return result


def convert_ip_address(data):
    ip_addr=list()
    for i in data:
        ip_addr.append(str(int(i.hex(),16)) ) 
    ip_addr=".".join(ip_addr)
    return ip_addr

def parsing_TCP_header(data):
    print("=============tcp header==============")
    TCP_header=struct.unpack("!2s2s1I1I2s2s2s2s",data)

    src_port=int(TCP_header[0].hex(),16)
    print("src_port:",src_port)

    dec_port=int(TCP_header[1].hex(),16)
    print("dec_port:",dec_port)

    seq_num=TCP_header[2]
    print("seq_num:",seq_num)

    ack_num=TCP_header[3]
    print("ack_num:",ack_num)

    header_len=(int(TCP_header[4].hex(),16)>>12)&0xf
    print("header_len:",header_len)

    flags=int(TCP_header[4].hex(),16)&0x0fff
    print("flags:",flags)

    reserved=(flags>>9)&0x007
    print(">>>reserved",reserved)

    nonce=(flags>>8)&0x001
    print(">>>nonce:",nonce)

    cwr=(flags>>7)&0x001
    print(">>>cwr:",cwr)

    urgent=(flags>>5)&0x001
    print(">>>urgent:",urgent)

    ack=(flags>>4)&0x001
    print(">>>ack:",ack)

    push=(flags>>3)&0x001
    print(">>>push:",push)

    reset=(flags>>2)&0x001
    print(">>>reset:",reset)

    syn=(flags>>1)&0x001
    print(">>>syn:",syn)

    fin=flags&0x001
    print(">>>fin:",fin)

    window_size=int(TCP_header[5].hex(),16)
    print("Window_size_value:",window_size)

    checksum=int(TCP_header[6].hex(),16)
    print("checksum:",checksum)

    urgent_pointer=int(TCP_header[7].hex(),16)
    print("urgent_pointer:",urgent_pointer)

def parsing_UDP_header(data):
    UDP_header=struct.unpack("2s2s2s2s",data)
    print("=============udp_header=============")

    src_port=int(UDP_header[0].hex(),16)
    print("src_port:",src_port)

    dst_port=int(UDP_header[1].hex(),16)
    print("dst_port:",dst_port)

    leng=int(UDP_header[2].hex(),16)
    print("leng:",leng)

    header_checksum=UDP_header[3].hex()
    print("header_checksum:0x",header_checksum)



recv_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0800))

print("<<<<<<Packet Capture Start>>>>>>>")

while True:
    
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    parsing_ip_header(data[0][14:34])

    flag =ch_UDP_TCP(data[0][23:24])
   
    if flag==6:
     parsing_TCP_header(data[0][34:54])

    elif flag==17:
     parsing_UDP_header(data[0][34:42])
     
     
