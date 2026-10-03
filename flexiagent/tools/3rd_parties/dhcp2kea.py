#!python3
#
# Copyright (C) 2018-2023 Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# dhcp2kea by marmo
# 6-12-2022 (dhcpd4), 14-12-2022 (dhcpd6), 15-12-2022 (dhcp2kea.php)
# 23-12-2022 ("addr key=value" option)
#
# https://gitlab.isc.org/isc-projects/kea/-/wikis/keama-leases
# https://gitlab.isc.org/isc-projects/keama-leases
# https://linux.die.net/man/5/dhcpd.leases
# https://kb.isc.org/docs/isc-dhcp-41-manual-pages-dhcpdleases
    
# code:

import os      # using os.path.exists
import time    # using time.strptime
import struct  # using struct.unpack
import re      # using re.search

class Leases:
    """
    leases container
    - could be initiated from filename or string with dict of default values
    - detects dhcp6 by checking if file contains "ia-"
    - _process() constructs dictionary of leases from splited strings
    - str - conversion to string constructs csv string
    - repr - internal string for debugging
    """
    def __init__(self, data, dic={}) : # initializer from file or string data
        self.leases = {}               # dictionary of processed leases
        self.dic = dic                 # dicionary of defualt values
        self.ver = 4                   # defaults to dhcpd4
        self.processed = 0
        self.written = 0 
        lines = os.path.exists(data) and open(data,'r') or data.split("\n")
        s = ''
        for l in lines:        # parsing leases lines
            if l.startswith("ia-"): self.ver=6  # change to dhcpd6
            if l.startswith("lease ") or l.startswith("ia-"): # begin of laese
                l = l.replace("{",";")
                s = ''
            if l.startswith("}"):  # end of lease
                self._process([s.replace("{",";").split(";")])  # processing a lease
            s += l.strip()
        return
    def _process(self,leases):     # processing array of strings
        for l in leases:
            self.processed += 1
            if l[0].startswith("lease ") or l[0].startswith("ia-"):
                dd = {"uid":"","subnet_id":"1","client-hostname":""
                     ,"set ddns-fwd-name =":"","iaaddr":"","lease_type":"" 
                     ,"prefix_len":"","hwaddr":"","state":"0","user_context":""
                     ,"hwtype":"","hwaddr_source":"" 
                     }  # default values
                dd.update(self.dic)
                if l[0] in self.leases:     # python2: self.leases2.has_key(l[0]):    
                    dd = self.leases[l[0]]  # values from existing lease dict
                for i in range(1,len(l)):   # scan for new values
                    ss = l[i].strip(';').strip().split(" ")
                    try:
                        t=time.mktime(time.strptime(' '.join(ss[2:4]),"%Y/%m/%d %H:%M:%S"))
                        dd[ss[0]]=int(t)    # time in miliseconds since 1-1-1970
                    except:
                        if len(ss)>1 and ss[1].startswith("never"):   # ticket #6 
                            dd[ss[0]]=int(time.mktime((2037,1,1, 0,0,0, 0,0,0))) # 1-1-2037
                            dd["valid_lifetime"]=0xFFFFFFFF           # max_unit32
                        else:
                            dd[' '.join(ss[0:len(ss)-1])]=ss[len(ss)-1]
                self.leases[l[0]] = dd
                for k,v in self.leases[l[0]].items():  # update lease for dhcp4 and dhcp6
                    if k.startswith("lease "):
                        a = k.split(' ')[1]
                        if re.search(a, self.ver==4 and l[0] or self.leases[l[0]]["iaaddr"]):
                            self.leases[l[0]].update(v)
    def __repr__(self):            # string representing internal state 
        s = ''
        for k,v in self.leases.items():
            s += k + ':' + '\n'
            for k2,v2 in v.items():
                s += "    " + k2 + " : " + str(v2) + '\n'
        for k,v, in self.dic.items():
            s += k + " : " + str(v) + '\n'
        return s
    def __str__(self):         # leases to csv string
        s4 = 'address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n'
        s6 = 'address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source\n'
        s = s4 if self.ver == 4 else s6
        self.written = 0
        for k,v in self.leases.items():
            if "binding state" in v and v["binding state"].startswith("free"): # ticket #4
                continue                                                       # skip free leases
            self.written += 1
            max_life = (self.ver==4) and (v["ends"]-v["starts"]) or v["max-life"] 
            if "valid_lifetime" in v : 
                max_life = v["valid_lifetime"]
            if "expire" in v :
                v["ends"] = v["expire"]==0 and time.mktime(time.localtime())+int(max_life) or v["expire"]
            if self.ver == 4:
                a = [ k.split(' ')[1] # address
                , v["hardware ethernet"] # hwaddr
                , ':'.join([format((ord(x)),'02x') for x in v["uid"].encode('utf-8').decode('unicode-escape')[1:-1]])
                , str(int(max_life)) # valid_lifetime
                , str(v["ends"]) # expire
                , v["subnet_id"]  # subnet_id
                , len(v["client-hostname"])>0 and "1" or "0" # fqdn_fwd
                , len(v["client-hostname"])>0 and "1" or "0" # fqdn_rev
                , v["client-hostname"][1:-1].replace(',',"&#x2c") # hostname
                , str(v["state"])  # "0" # state
                , str(v["user_context"]) # user_context
                ] 
            if self.ver == 6:
                iaid,duid = "",k.split(' ')[1]
                if duid.startswith('"'):
                    t = duid.encode('utf-8').decode('unicode-escape')[1:-1]
                    t1 = ':'.join([format((ord(x)),'02x') for x in t])
                    iaid = struct.unpack('i',str.encode(t[0:4]))[0]
                    duid = t1[4*3:]
                addr = v["iaaddr"]
                if ("iaprefix" in v):
                    addr = v["iaprefix"] 
                a = [ addr # address
                , duid # duid
                , str(int(max_life)) # valid_lifetime
                , str(v["ends"]) # expire
                , v["subnet_id"] # subnet_id
                , str(v["preferred-life"]) # pref_liftime
                , str(v["lease_type"])     # lease_type
                , str(iaid) # iaid
                , str(v["prefix_len"]) # prefix_len
                , len(v["set ddns-fwd-name ="])>0 and "1" or "0" # fqdn_fwd
                , len(v["set ddns-fwd-name ="])>0 and "1" or "0" # fqdn_rev
                , v["set ddns-fwd-name ="][1:-1].replace(',',"&#x2c") # hostname
                , str(v["hwaddr"]) # "" # hwaddr
                , str(v["state"]) # "0" # state
                , str(v["user_context"]) # "" # user_context
                , str(v["hwtype"]) # # hwtype
                , str(v["hwaddr_source"]) # # hwaddr_source
                ]
            s += ','.join(a)+'\n'
        return s

# example leases:

dhcpd4leases=r'''
# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.4.2

# authoring-byte-order entry is generated, DO NOT DELETE
authoring-byte-order little-endian;

server-duid "\000\001\000\001'\217@\304\010\000'\307\306";

lease 175.16.1.100 {
  starts 1 2021/01/11 17:00:56;
  ends 1 2021/01/11 17:05:56;
  cltt 1 2021/01/11 17:00:56;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 08:00:27:ca:dd:fc;
  client-hostname "cserver";
}
lease 175.16.1.101 {
  starts 1 2021/01/11 17:00:57;
  ends 1 2021/01/11 17:05:57;
  cltt 1 2021/01/11 17:00:57;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 08:00:27:80:3c:9d;
  client-hostname "cclient";
}
lease 175.16.1.100 {
  starts 1 2021/01/11 17:00:56;
  ends 1 2021/01/11 17:05:56;
  tstp 1 2021/01/11 17:05:56;
  cltt 1 2021/01/11 17:00:56;
  binding state free;
  hardware ethernet 08:00:27:ca:dd:fc;
}
lease 175.16.1.101 {
  starts 1 2021/01/11 17:00:57;
  ends 1 2021/01/11 17:05:57;
  tstp 1 2021/01/11 17:05:57;
  cltt 1 2021/01/11 17:00:57;
  binding state free;
  hardware ethernet 08:00:27:80:3c:9d;
}
'''

dhcpd6leases=r'''
# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.4.2

# authoring-byte-order entry is generated, DO NOT DELETE
authoring-byte-order little-endian;

server-duid 00:01:00:01:28:f8:2c:53:08:00:27:c7:c6:20;

ia-na cc:bb:aa:00:00:03:00:01:31:32:33:34:35:36 {
  cltt 2 2021/10/12 11:22:10;
  iaaddr 3002::200 {
    binding state active;
    preferred-life 225;
    max-life 360;
    ends 2 2021/10/12 11:28:10;
    set ddns-fwd-name = "toms.four.example.com";
    set ddns-dhcid = "\000\002\001'\223`\344\240\350\230:[\264\220va3p-\335R\253\233\215\354\315%\346\034_\351\206k\002\224";
    set ddns-rev-name = "0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.3.ip6.arpa.";
  }
}

server-duid 00:01:00:01:28:f8:2c:53:08:00:27:c7:c6:20;

ia-na cc:bb:aa:00:00:03:00:01:31:32:33:34:35:36 {
  cltt 2 2021/10/12 11:22:10;
  iaaddr 3002::200 {
    binding state expired;
    preferred-life 225;
    max-life 360;
    ends 2 2021/10/12 11:28:10;
  }
}

'''

# tests

def test(n=0, dic={}, debug=False):
    print("dhcpd leases conversion tests:")
# dhcp4 file tests
    if n==1 or n==0:
        print("(1)")
        fname="example1-dhcpd4.leases"
        leases = Leases(fname,dic)         # reading
        if debug: print(repr(leases))
        print(fname,":\n",leases)          # writing
        print("processed:",leases.processed,"written:",leases.written)
# dhcp6 file tests
    if n==2 or n==0:
        print("(2)")
        fname="example2-dhcpd6.leases"
        leases = Leases(fname,dic)         # reading
        if(debug): print(repr(leases))
        print(fname,":\n",leases)          # writing
        print("processed:",leases.processed,"written:",leases.written)
    if n==3 or n==0:
        print("(3)")
        fname="example3-dhcpd6.leases"
        leases = Leases(fname,dic)         # reading
        if(debug): print(repr(leases))
        print(fname,":\n",leases)          # writing
        print("processed:",leases.processed,"written:",leases.written)
# dhcp4 string test
    if n==4 or n==0:
        print("(4)")
        leases = Leases(dhcpd4leases,dic)  # reading
        if(debug): print(repr(leases))
        print(leases)          # writing
        print("processed:",leases.processed,"written:",leases.written)

# dhcp6 string test
    if n==6 or n==0:
        print("(6)")
        leases = Leases(dhcpd6leases,dic)  # reading
        if(debug): print(repr(leases))
        print(leases)          # writing
        print("processed:",leases.processed,"written:",leases.written)

 
# main

usage="""
Usage: python3 dhcp2kea.py ["[addr ]key=value"] [-e[dateTtime] [-v] [-h] [-d] [-t] leases-filename(s)
Options:
  -h : help - prints this help
  -v : verbose - print results to stdout
  -d : debug - print internal state
  "key=value" : default values for each lease
  "addr key=value" : default value for addr
  -e[dateTtime] : expire - overriding expire value with datetime (defaults to current)
  -t[n] : test - execute test/demo functions, optional n=1,2,3,4,6 (internal test no) defaults to all
Key names:
  uid, subnet_id, client-hostname, lease_type, prefix_len, 
  hwaddr, state, user_context, hwtype, hwaddr_source, 
  expire, valid_liftime
Examples:
  1.setting subnet_id=2 for all leases:
    python3 dhcp2kea.py "subnet_id=2" example1-dhcpd4.leases
  2.setting subnet_id=3 for 192.168.1.12 to 192.168.1.16 and subnet_id=2 for 192.168.1.20 to 192.168.1.29
    python3 dhcp2kea.py "192.168.1.1[2-6] subnet_id=3" "192.168.1.2\d subnet_id=2" example1-dhcpd4.leases
  3.setting subnet_id=3 for 192.168.1.12 and subnet_id=8 for 3ffe:501:ffff:100::c9d9 in two processed files
    python3 dhcp2kea.py "192.168.1.12 subnet_id=3" example1-dhcpd4.leases "3ffe:501:ffff:100::c9d9 subnet_id=8" example2-dhcpd6.leases
  4.setting expiration time to January,4th 2023 10 o'clock localtime for all leases
    python3 dhcp2kea.py -e2023/01/04T10:00:00 example1-dhcpd4.leases
  5.setting liftime of each lease starting from current time for internal test no 6 (dhcp6 string)
    python3 dhcp2kea.py "valid_liftime=3600" -e -t6
"""

if __name__ == "__main__":
    import sys       # using sys.argv
    import os        # using os.path.exists

    dic = {}         # default dictionary for each lease 
    verbose = False  # writing converted file content to stdout
    debug = False    # for printing internal state
    expire = 0       # extend lease liftime option
    if len(sys.argv)>1:
#        for i in range(1,len(sys.argv)):
        i = 1
        while (i<len(sys.argv)):
            ss=sys.argv[i].split("=")   # detect key=value arg
            if len(ss)>1:
                sss=ss[0].split(" ")    # detect "addr key=value" arg
                if len(sss)>1:
                    dic["lease "+sss[0]+" "] = {sss[1]:ss[1]}
                else:
                    dic[ss[0]] = ss[1]  # insert into leases dictionary
            elif sys.argv[i][0]!='-':
                fname = sys.argv[i]
                if os.path.exists(fname):
                    leases = Leases(fname,dic)    # reading
                    with open(fname.replace('.','-')+"-kea.csv","w") as f:
                        print(leases,file=f)  # writing
                        if verbose: print(fname+":") 
                        if debug: print(repr(leases))
                        if verbose: 
                            print(leases) 
                            print("    processed:",leases.processed,end=" ")
                            print("    written:",leases.written)
                else: print(fname+' not found')
            else:
                if sys.argv[i][1]=='v':
                    verbose = True
                if sys.argv[i][1]=='t':
                    test(len(sys.argv[i])>2 and int(sys.argv[i][2:]) or 0, dic, debug)
                if sys.argv[i][1]=='h':
                    print(usage)
                if sys.argv[i][1]=='d':
                    debug = True
                if sys.argv[i][1]=='e':
                    expire = 0 # time.mktime(time.localtime())
                    if len(sys.argv[i]) > 2:
                       try:expire = time.mktime(time.strptime(sys.argv[i][2:],"%Y/%m/%dT%H:%M:%S"))
                       except: pass
                    dic["expire"] = int(expire) 
            i += 1  # next arg
    else:
        print(usage)

"""
end
"""
