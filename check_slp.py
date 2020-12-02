#!/usr/bin/env python3

# SRVLOC / SLP protocol dissector for Scapy
# Written by Hynek Petrak

import getopt
import re
import sys
import binascii
import struct
import socket
import os
import logging
import ipaddress
from random import randint
from scapy.fields import (
    BitField,
    BoundStrLenField,
    ByteEnumField,
    ByteField,
    FieldLenField,
    FlagsField,
    IntField,
    PacketListField,
    ShortField,
    StrField,
    ThreeBytesField,
    XShortField,
    ConditionalField,
    PacketField,
)
from scapy.packet import Packet, bind_layers
from scapy.error import Scapy_Exception
from scapy.volatile import RandShort

log = logging.getLogger(__file__)

class ThreeBytesLenField(FieldLenField):
    def __init__(self, name, default, length_of=None, adjust=lambda pkt, x: x):
        FieldLenField.__init__(self, name, default, length_of=length_of,
                               fmt='!I', adjust=adjust)

    def i2repr(self, pkt, x):
        if x is None:
            return 0
        return repr(self.i2h(pkt, x))

    def addfield(self, pkt, s, val):
        return s + struct.pack(self.fmt, self.i2m(pkt, val))[1:4]

    def getfield(self, pkt, s):
        return s[3:], self.m2i(pkt, struct.unpack(self.fmt, b"\x00" + s[:3])[0])  # noqa: E501


class SLPSrvRqst(Packet):
    name = "SLPSrvRqst"
    fields_desc = [
        FieldLenField("prlist_len", None, length_of="prlist"),
        BoundStrLenField("prlist", b"", length_from=lambda x: x.prlist_len),
        FieldLenField("service_type_len", None, length_of="service_type"),
        BoundStrLenField("service_type", b"",
                         length_from=lambda x: x.service_type_len),
        FieldLenField("scope_list_len", None, length_of="scope_list"),
        BoundStrLenField("scope_list", b"DEFAULT",
                         length_from=lambda x: x.scope_list_len),
        FieldLenField("predicate_len", None, length_of="predicate"),
        BoundStrLenField("predicate", b"",
                         length_from=lambda x: x.predicate_len),
        FieldLenField("slp_spi_len", None, length_of="slp_spi"),
        BoundStrLenField("slp_spi", b"", length_from=lambda x: x.slp_spi_len),
    ]


class SLPURLEntry(Packet):
    name = "SLPURLEntry"
    fields_desc = [
        ByteField("reserved", 0),
        ShortField("lifetime", 0),
        FieldLenField("url_len", None, length_of="url"),
        BoundStrLenField("url", b"", length_from=lambda x: x.url_len)
    ]

    def extract_padding(self, p):
        #        log.debug("URL >>>> ", p)
        return "", p


class SLPAuthBlock(Packet):
    name = "SLPAuthBlock"
    fields_desc = [
        XShortField("block_structure_descriptor", 0),
        ShortField("auth_block_len", 0),
        IntField("timestamp", 0),
        FieldLenField("slp_spi_len", None, length_of="slp_spi"),
        BoundStrLenField("slp_spi", b"", length_from=lambda x: x.slp_spi_len),
        BoundStrLenField(
            "auth_block", b"", length_from=lambda x: x.auth_block_len - x.slp_spi_len - 8)
    ]

    def extract_padding(self, p):
     #       log.debug("Auth >>>> ", p)
        return "", p


class SLPSrvRply(Packet):
    name = "SLPSrvRply"
    fields_desc = [
        ShortField("error_code", 0),
        FieldLenField("url_entry_count", None, count_of="url_entries"),
        PacketListField("url_entries", [], SLPURLEntry,
                        count_from=lambda pkt: pkt.url_entry_count),
        FieldLenField("auth_blocks_cnt", None, fmt="b", count_of="auth_blocks"),
        PacketListField("auth_blocks", [], SLPAuthBlock,
                        count_from=lambda pkt: pkt.auth_blocks_cnt),
        # http://www.networksorcery.com/enp/rfc/rfc2608.txt
        # https://github.com/secdev/scapy/blob/620dc579d3a220793f41eb697e5209c9376e80bc/scapy/contrib/portmap.py
    ]


class SLPAttrRqst(Packet):
    name = "SLPAttrRqst"
    fields_desc = [
        FieldLenField("prlist_len", None, length_of="prlist"),
        BoundStrLenField("prlist", b"", length_from=lambda x: x.prlist_len),
        FieldLenField("url_len", None, length_of="url"),
        BoundStrLenField("url", b"",
                         length_from=lambda x: x.url_len),
        FieldLenField("scope_list_len", None, length_of="scope_list"),
        BoundStrLenField("scope_list", b"DEFAULT",
                         length_from=lambda x: x.scope_list_len),
        FieldLenField("tag_list_len", None, length_of="tag_list"),
        BoundStrLenField("tag_list", b"",
                         length_from=lambda x: x.tag_list_len),
        FieldLenField("slp_spi_len", None, length_of="slp_spi"),
        BoundStrLenField("slp_spi", b"", length_from=lambda x: x.slp_spi_len),
    ]


class SLPAttrRply(Packet):
    name = "SLPAttrRply"
    fields_desc = [
        ShortField("error_code", 0),
        FieldLenField("attr_list_len", None, length_of="attr_list"),
        BoundStrLenField("attr_list", b"",
                         length_from=lambda x: x.attr_list_len),
        FieldLenField("auth_blocks_cnt", None, fmt="b", count_of="auth_blocks"),
        PacketListField("auth_blocks", [], SLPAuthBlock,
                        count_from=lambda pkt: pkt.auth_blocks_cnt),
    ]


class SLPSrvTypeRqst(Packet):
    name = "SLPSrvTypeRqst"
    fields_desc = [
        FieldLenField("prlist_len", None, length_of="prlist"),
        BoundStrLenField("prlist", b"", length_from=lambda x: x.prlist_len),
        FieldLenField("naming_auth_len", None, length_of="naming_auth"),
        BoundStrLenField(
            "naming_auth", b"", length_from=lambda x: x.naming_auth_len if x.naming_auth_len < 0xffff else 0),
        FieldLenField("scope_list_len", None, length_of="scope_list"),
        BoundStrLenField("scope_list", b"DEFAULT",
                         length_from=lambda x: x.scope_list_len),
    ]


class SLPSrvTypeRply(Packet):
    name = "SLPSrvTypeRply"
    fields_desc = [
        ShortField("error_code", 0),
        FieldLenField("srvtype_list_len", None, length_of="srvtype_list"),
        BoundStrLenField("srvtype_list", b"",
                         length_from=lambda x: x.srvtype_list_len)
    ]


SLP_FN1_SRVRQST = 1
SLP_FN2_SRVRPLY = 2
SLP_FN6_ATTRRQST = 6
SLP_FN7_ATTRRPLY = 7
SLP_FN9_SRVTYPERQST = 9
SLP_FN10_SRVTYPERPLY = 10

_function_classes = {
    SLP_FN1_SRVRQST: SLPSrvRqst,
    SLP_FN2_SRVRPLY: SLPSrvRply,
    SLP_FN6_ATTRRQST: SLPAttrRqst,
    SLP_FN7_ATTRRPLY: SLPAttrRply,
    SLP_FN9_SRVTYPERQST: SLPSrvTypeRqst,
    SLP_FN10_SRVTYPERPLY: SLPSrvTypeRply,
}

_function_names = {
    k: v().name for k, v in _function_classes.items()
}


class SLPExtension(Packet):
    name = "SLPExtension"
    __slots__ = ["my_offset", "pkt_len"]
    fields_desc = [
        XShortField("ext_id", 0),
        ThreeBytesField("next_ext_off", 0),
        BoundStrLenField("data", b"",
                         length_from=lambda pkt, *args: pkt._length_from(pkt, *args))
    ]

    @classmethod
    def _length_from(cls, x):
        ext_end = x.next_ext_off if x.next_ext_off else x.pkt_len
        r = max(0, ext_end - x.my_offset - 5)
        #log.debug(f"Ext: my_len {r} next_off {x.next_ext_off} my_off {x.my_offset} total {x.pkt_len}")
        if ext_end > x.pkt_len:
            raise Scapy_Exception("%s: malformed packet, extension exceeds packet length" %
                                  cls.__name__)
        return r

    # https://github.com/secdev/scapy/blob/cfe00d5c952e9048a40150390e0025b5ceff7228/scapy/layers/bluetooth.py#L485
    def __init__(self, _pkt=None, offset=0, pkt_len=0, **kwargs):
        self.my_offset = offset
        self.pkt_len = pkt_len
        Packet.__init__(self, _pkt, **kwargs)

    def extract_padding(self, p):
        return "", p


class SLPv2(Packet):
    name = "SLPv2"
    __slots__ = ["ext_len"]
    fields_desc = [ByteField("version", 2),
                   ByteEnumField("function", 1, _function_names),
                   ThreeBytesField("length", None),
                   FlagsField("flags", 0, 3, "OFR"),
                   BitField("reserved", 0, 13),
                   # TODO: handle sending extententions
                   # http://www.networksorcery.com/enp/rfc/rfc2608.txt Section 9.1
                   ThreeBytesField("next_ext_off", 0),
                   XShortField("xid", RandShort()),
                   FieldLenField("lang_tag_len", None, length_of="lang_tag"),
                   BoundStrLenField("lang_tag", b"en",
                                    length_from=lambda x: x.lang_tag_len),
                   ConditionalField(PacketListField("extensions", [], SLPExtension,
                                                    next_cls_cb=lambda pkt, *args: pkt._next_cls_cb(pkt, *args)),
                                    # next_cls_cb=lambda pkt, lst, cur, remain:
                                    # SLPExtension if pkt.value_follows == 1 and
                                    # (len(lst) == 0 or cur.value_follows == 1) and
                                    # len(remain) > 4 else None),
                                    lambda pkt: pkt.next_ext_off > 0)
                   ]

    @classmethod
    def _next_cls_cb(cls, pkt, lst, cur, remain):
        next_off = pkt.next_ext_off if cur is None else cur.next_ext_off
        if next_off == 0:
            return None
        if next_off + 5 > pkt.length:
            raise Scapy_Exception("%s: malformed packet, extension header exceeds packet length" %
                                  cls.__name__)
        if cur is None and next_off < 15:
            raise Scapy_Exception("%s: malformed packet, extension points to header" %
                                  cls.__name__)
        if cur is not None and cur.next_ext_off <= cur.my_offset + 5:
            raise Scapy_Exception("%s: malformed packet, extension overlap" %
                                  cls.__name__)

        return lambda *args: SLPExtension(*args, offset=next_off, pkt_len=pkt.length)

    # for fn, cls in _function_classes.items():
    #    def get_conditional_field(fn, cls):
    #        return ConditionalField(
    #            PacketField("slp_body", cls(), cls),
    #            lambda pkt: pkt.function == fn
    #        )
    #    fields_desc.append(get_conditional_field(fn, cls))

    def guess_payload_class(self, payload):
        ret = _function_classes.get(self.function)
        #log.debug("Guess next payload", ret)
        return ret

    # def extract_padding(self, p):
    #    log.debug(p)
    #    return "", p

    def pre_dissect(self, s):
        # move extensions
        # log.debug(s)
        length = struct.unpack("!I", b"\x00" + s[2:5])[0]
        next_ext_offset = struct.unpack("!I", b"\x00" + s[7:10])[0]
        lang_tag_len = struct.unpack("!H", s[12:14])[0]
        header_len = 14 + lang_tag_len
        #log.debug("Len ", length, len(s), next_ext_offset, header_len)
        self.ext_len = 0
        if length > len(s):
            raise Exception("%s: malformed packet, shorter than header length" %
                            cls.__name__)
        if next_ext_offset == 0:
            return s
        self.ext_len = len(s) - next_ext_offset
        #log.debug("ext_len", self.ext_len)
        # Dropping whats behind length from header,swap payload and extensions
        ret = s[:header_len] + s[next_ext_offset:length] + \
            s[header_len:next_ext_offset]  # [:4] + s[-3:] + s[4:-3]
        # log.debug(s)
        # log.debug(ret)
        return ret

    def post_build(self, p, pay):
        if len(self.extensions) > 0:
            raise NotImplementedError("Sending extensions not implemented yet")
        if self.length is None:
            tmp_len = len(pay) + len(p)  # + 1  # +len(p)
            #log.debug(p, tmp_len)
            p = p[:2] + struct.pack("!I", tmp_len)[1:4] + p[5:]
        return p + pay


for fn, cls in _function_classes.items():
    bind_layers(SLPv2, cls, function=fn)


def main():
    log.setLevel(logging.INFO)
    # create file handler which logs even debug messages
    fh = logging.FileHandler(__file__ + ".log")
    fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    # ch.setLevel(logging.WARNING)
    ch.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the log
    log.addHandler(fh)
    log.addHandler(ch)

    version = '0.4'
    mode = 'unicast'
    source = 'N/A'
    target = 'N/A'
    xid = b'\x12\x34'
    port = 427
    target_file = None

    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        print('Usage : ' +
              sys.argv[0] + ' <targets_file>')
        print('\t<targets_file> File with Target IP Adresses, one per line')
        sys.exit(1)

    def checkArguments():
        if (mode == 'multicast'):
            # XID : must be 0 in multicast mode
            # Target IP : default SLP multicast address
            # Source IP : address of the local interface
            global xid
            xid = '\x00\x00'
            log.info('Forcing XID to "0"')
            global target
            target = '239.255.255.253'
            log.info('Forcing target IP to "' + target + '"')
            if (source != 'N/A'):
                log.info('Forcing source IP to "' + source + '"')
            else:
                log.info('You need to force the source address with "-s" !')
                showUsage()
        elif (mode == 'unicast') or (mode == 'broadcast') or (mode == 'multicast') or (mode == 'tcp'):
            # Target IP : must be defined
            if (target == 'N/A' and target_file is None):
                log.info('Invalid target !')
                showUsage()
        else:
            log.info('Invalid mode !')
            showUsage()


    # Send via TCP

    def sendTcpPacket(packet):

        log.info('Sending packet via TCP [' + target + ']')

        req = SLPv2()/SLPSrvRqst(service_type=b'service:directory-agent') # 1
        packet = bytes(req)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try:
            s.connect((target, port))
        except socket.error:
            log.info('Socket error (port closed ?)')
            sys.exit(1)
        s.send(packet)
        s.close

    # Send via unicast UDP

    def sendUnicastPacket(target):

        log.info(f'[{target}] Sending packet via Unicast UDP')
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            if False:
                packet = b'\x02\x06\x00\x00\x44\x00\x00\x00\x006\x124\x00\x02en\x00\x00\x00\x15http://www.examp.com/\x00\x07default\x00\x00\x00\x00\xba\xbe\x00\x00\x3d\x01\x02\xba\xbe\x00\x00\x00\x01\x02'
                req = SLPv2()/SLPSrvRqst(service_type=b'service:directory-agent') # 1
                log.debug(req.show2(True))
                req = SLPv2()/SLPAttrRqst(url=b'www.example.com') # 6
                log.debug(req.show2(True))


                req = SLPv2(packet)
                log.debug(req.show(True))
                #req = SLPv2(function=SLP_FN9_SRVTYPERQST, slp_body=SLPSrvTypeRqst(naming_auth_len=0xffff))

            if False:
                req = SLPv2()/SLPSrvRqst(service_type=b'service:directory-agent', scope_list=b'default') # 1
                log.info(req.show2(True))
                s.sendto(bytes(req), (target, port))
                data, address = s.recvfrom(4096)
                #log.debug(f"{data} {address}")
                resp = SLPv2(data)
                log.info(f'[{target}] DASrvRqst error: {resp.error_code}')
                log.info(resp.show(True))

            req = SLPv2()/SLPSrvTypeRqst(naming_auth_len=0xffff)
            log.debug(req.show2(True))

            s.sendto(bytes(req), (target, port))
            data, address = s.recvfrom(4096)
            #log.debug(f"{data} {address}")
            resp = SLPv2(data)
            log.debug(resp.show(True))

            log.info(f'[{target}] SLP Service detected')
            for srv_type in resp.srvtype_list.split(b","):
                req = SLPv2()/SLPSrvRqst(service_type=srv_type)
                log.debug(req.show2(True))

                s.sendto(bytes(req), (target, port))
                data, address = s.recvfrom(4096)
                #log.debug(f"{data} {address}")
                resp = SLPv2(data)
                log.debug(resp.show(True))

                for url_entry in resp.url_entries:
                    req = SLPv2()/SLPAttrRqst(url=url_entry.url)
                    log.debug(req.show2(True))

                    s.sendto(bytes(req), (target, port))
                    data, address = s.recvfrom(4096)
                    #log.debug(f"{data} {address}")
                    resp = SLPv2(data)
                    attr_list = resp.attr_list

                    log.debug(resp.show(True))

                    log.info(f"[{target}]\tATTR\t{url_entry.url.decode('utf-8')}\t{attr_list.decode('utf-8')}")
        except Exception as ex:
            log.error(f"[{target}]\t{repr(ex)}")


    def sendBroadcastPacket(packet):
        log.info('Sending packet via Broadcast UDP [' + target + ']')

        req = SLPv2()/SLPSrvRqst(service_type=b'service:directory-agent') # 1
        packet = bytes(req)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (target, port))


    def sendMulticastPacket(packet):
        log.info('Sending packet via Multicast UDP [' + target + ']')

        req = SLPv2()/SLPSrvRqst(service_type=b'service:directory-agent') # 1
        packet = bytes(req)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.bind((source, 6666))  # Select an interface (and an evil port ;-)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.sendto(packet, (target, port))


    if target_file:
        with open(target_file, 'r') as f:
            nets = f.read().splitlines()
            hosts = list(set([str(ip) for net in nets for ip in ipaddress.IPv4Network(net)]))

            import concurrent.futures
            th = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                for ip in hosts:
                    ft_dp = executor.submit(sendUnicastPacket, ip)
                    th.append(ft_dp)
                for r in concurrent.futures.as_completed(th):
                    pass

    else: # Inactive code
        # TCP
        if (mode == 'tcp'):
            sendTcpPacket()
        # UDP
        elif (mode == 'unicast'):
            sendUnicastPacket(target)
        elif (mode == 'broadcast'):
            sendBroadcastPacket()
        elif (mode == 'multicast'):
            sendMulticastPacket()

    log.info('Exit')

if __name__ == "__main__":
    main()
