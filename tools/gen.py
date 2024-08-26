import re
import os
import json
import sys
import ipaddress
import struct
import socket

# Rule format
#
# <matches, nftables syntax*> actions <list actions>
#
# # Filter support (*):
#
#  - ip
#  - saddr [!=]: match source IP against IP or CIDR
#                e.g. `saddr 10.0.0.1` or `saddr 10.0.0.0/24`
#  - daddr [!=]: match destination IP against IP or CIDR
#  - tcp
#  - udp
#  - sport [!=]: match L4 source port (single port, no range)
#                e.g. `sport 80`
#  - dport [!=]: match L4 destination port
#
# saddr/daddr and sport/dport support negation using `!=`. E.g.
#
# `ip saddr 127.0.0.1 daddr != 127.0.0.0/24 udp sport != 65000 dport 2055`
#
# # Action support:
#
#  - funnel: funnel packet through tcp or udp, and using sport/dport specified
#            e.g. `funnel tcp sport 650 dport 179`
#  - unfunnel: unfunnel packet and assign ip_proto
#            e.g. `unfunnel udp`
#  - dnat: set destination IP [NOT SUPPORTED]
#  - accept: stop processing rules, but do not touch the packet.
#  - drop: drop the packet
#
#  `accept` and `drop` are exclusve (no other action supported)
#
# # Matching
#
# Matching algorithm is a linear lookup, following the strict order of rules
# given. Upon match, actions are executed, and processing of the packet
# by tc_sfunnel terminates.
#

INDENT="  "
param_re="(\S+)"
neg_re="(!\s*=)?"

match_patterns = [
    "(ip)",
    f"(saddr)\s*{neg_re}\s*{param_re}",
    f"(daddr)\s*{neg_re}\s*{param_re}",
    "(tcp)",
    "(udp)",
    f"(sport)\s*{neg_re}\s*{param_re}",
    f"(dport)\s*{neg_re}\s*{param_re}"
]

action_patterns = [
    f"(funnel)\s*{param_re}\s*(sport|dport)\s*{param_re}\s*(sport|dport)\s*{param_re}",
    f"(unfunnel)\s*{param_re}",
    f"(dnat)\s*{param_re}",
    f"(accept)",
    f"(drop)"
]

#Parsing routines
#TODO: we need a proper lex parser... sigh
def extract_matches(string: str):
    s = string
    matches={}
    for m_it in match_patterns:
        pattern = rf'\s*{m_it}\s*'
        re_m = re.search(pattern, s)
        if not re_m:
            continue
        grp_len = len(re_m.groups())
        if grp_len not in [1,2,3]:
            raise Exception(f"ERROR: parsing '{m_it}' in '{string}'")
        m = {}
        if grp_len == 2:
            m["value"] = re_m.groups()[1]
        elif grp_len == 3:
            if re_m.groups()[1] == "!=":
                m["neg"] = 1
            m["value"] = re_m.groups()[2]

        matches[re_m.groups()[0]] = m
        s = re.sub(pattern, "", s)

    if s != "":
        raise ValueError(f"ERROR: unable to parse '{s}' from '{string}'")

    return matches

def extract_actions(string: str):
    s = string
    actions={}
    for a_it in action_patterns:
        pattern = rf'\s*{a_it}\s*'
        re_a = re.search(pattern, s)
        if not re_a:
            continue
        grp_len = len(re_a.groups())
        if grp_len not in [1,2,6]:
            raise Exception(f"ERROR: parsing '{a_it}' in '{string}'")
        a = {}
        if grp_len == 2:
            #Unfunnel/DNAT
            if re_a.groups()[0] == "unfunnel" and re_a.groups()[1] not in ["tcp", "udp"]:
                raise ValueError(f"ERROR: protocol following unfunnel action must be 'tcp' or 'udp' in '{string}'")
            a["value"] = re_a.groups()[1]
        elif grp_len == 6:
            #Funnel
            if re_a.groups()[1] not in ["tcp", "udp"]:
                raise ValueError(f"ERROR: protocol following funnel action must be 'tcp' or 'udp' in '{string}'")
            a["fun_proto"] = re_a.groups()[1]
            if re_a.groups()[2] not in ["sport", "dport"]:
                raise ValueError(f"ERROR: unknown heade field '{re_a.groups()[3]}' in '{string}'")
            a[re_a.groups()[2]] = re_a.groups()[3]
            if re_a.groups()[4] not in ["sport", "dport"]:
                raise ValueError(f"ERROR: unknown heade field '{re_a.groups()[3]}' in '{string}'")
            a[re_a.groups()[4]] = re_a.groups()[5]

        actions[re_a.groups()[0]] = a
        s = re.sub(pattern, "", s)

    if s != "":
        raise ValueError(f"ERROR: unable to parse '{s}' from '{string}'")

    return actions

def extract_tuples(string):
    r = string.split("actions")
    if len(r) != 2:
        raise ValueError(f"ERROR: keyword 'actions missing or unable to parse in rule '{string}'")

    matches = extract_matches(r[0])
    actions = extract_actions(r[1])
    return matches, actions

def gen_ip_match(field: str, m: dict, indent: str):
    network = ipaddress.IPv4Network(m["value"], strict=False)
    ip = socket.htonl(int(network.network_address))
    mask = socket.htonl(int(network.netmask))
    neg = m["neg"] if "neg" in m else "0"

    s =  f"{indent}.{field} = {{"
    s += f" .negate = {neg},"
    s += f" .addr = 0x{ip:08x},"
    s += f" .mask = 0x{mask:08x}"
    s += f" }},\n"
    return s

def gen_port_match(field: str, m: dict, indent: str, end:str =","):
    neg = m["neg"] if "neg" in m else "0"
    port_nbo = socket.htons(int(m['value']))

    s =  f"{indent}.{field} = {{"
    s += f" .negate = {neg},"
    s += f" .port = 0x{port_nbo:04x}"
    s += f" }}{end}\n"
    return s

def __gen_ipproto(proto: str):
    return "IPPROTO_" + proto.strip().rstrip().upper()

def gen_matches(matches: str, indent: str):
    s = ""

    #ip addrs
    if "saddr" not in matches:
        matches["saddr"] = { "value": "0.0.0.0/0" }
    if "daddr" not in matches:
        matches["daddr"] = { "value": "0.0.0.0/0" }
    s += gen_ip_match("saddr", matches["saddr"], f"{indent}")
    s += gen_ip_match("daddr", matches["daddr"], f"{indent}")

    #proto
    if "tcp" not in matches and "udp" not in matches:
        raise ValueError(f"ERROR: tcp nor udp specified. One must be selected")
    proto = "tcp" if "tcp" in matches else "udp"
    s += f"{indent}.proto = {__gen_ipproto(proto)},\n"

    #L4 ports
    if "sport" not in matches:
        matches["sport"] = { "value": "0" }
    if "dport" not in matches:
        matches["dport"] = { "value": "0" }

    s += gen_port_match("sport", matches["sport"], f"{indent}")
    s += gen_port_match("dport", matches["dport"], f"{indent}", end="")

    return s

def gen_no_param_action(action: str, actions: dict, indent: str, end:str = ","):
    s =  f"{indent}.{action} = {{"
    s += f' .execute = { "1" if action in actions else "0" },'
    s += f" .p = {{{{0}}}} "
    s += f"}}{end}\n"
    return s

def gen_actions(actions: dict, indent: str):
    s = ""
    if ("accept" in actions or "drop" in actions) and len(actions) > 1:
        raise ValueError(f"ERROR: 'accept' and 'drop' actions are exclusve!")

    #TODO: remove when supported
    if "dnat" in actions:
        raise ValueError(f"ERROR: 'dnat' not yet supported!")

    s += gen_no_param_action("drop", actions, indent)
    s += gen_no_param_action("accept", actions, indent)

    if "funnel" in actions:
        proto = __gen_ipproto(actions["funnel"]["fun_proto"])
        f = actions['funnel']
        s +=  f"{indent}.funnel = {{ .execute = 1, .p = {{ .funnel = {{ .funn_proto = {proto}, .sport = {f['sport']}, .dport = {f['dport']} }} }} }},\n"
        pass
    else:
        s += gen_no_param_action("funnel", actions, indent)

    if "unfunnel" in actions:
        proto = __gen_ipproto(actions["unfunnel"]["value"])
        s +=  f"{indent}.unfunnel = {{ .execute = 1, .p = {{ .unfunnel = {{ .proto = {proto} }} }} }},\n"
    else:
        s += gen_no_param_action("unfunnel", actions, indent)
    if "dnat" in actions:
        network = ipaddress.IPv4Network(actions["dnat"]["value"], strict=False)
        addr_nbo = socket.htonl(int(network.network_address))
        s +=  f"{indent}.dnat = {{ .execute = 1, .p = {{ .dnat = {{ .daddr = 0x{addr_nbo:08x} }} }} }}\n"
    else:
        s += gen_no_param_action("dnat", actions, indent, end="")

    return s

#Generation
def gen_header(rules_str: str, rules: list):
    s =""
    guard="__SFUNNEL_GEN_RULES__"

    #Guards
    s += f"#ifndef {guard}\n"
    s += f"#define {guard}\n\n"

    #Store input as comment, just in case we need to debug
    s += f"/*\n"
    s += f" -- Autogenerated header file -- \n"
    s += f"Input:\n"
    s += f"{rules_str}"
    s += f"*/\n\n"

    s += "struct sfunnel_ip4_rule ip4_rules[] = {\n"
    for index, rule in enumerate(rules):
        s += f"{INDENT}{{\n"
        s += f'{2*INDENT}//{rule["__line__"]}\n'
        s += f'{2*INDENT}.id = {index},\n'
        s += f'{2*INDENT}.matches = {{\n'
        s += gen_matches(rule["matches"], f"{3*INDENT}")
        s += f'{2*INDENT}}},\n'
        s += f'{2*INDENT}.actions = {{\n'
        s += gen_actions(rule["actions"], f"{3*INDENT}")
        s += f'{INDENT}{INDENT}}}\n'
        s += f"{INDENT}}}"+ ("," if index != (len(rules) -1) else "") + "\n"
    s += "}; //ip4_rules\n"

    #End guard
    return s + "#endif //{guard}"

def usage():
    print("Usage:\n")
    print(f"sfunnel rules header generator")
    print(f"{sys.argv[0]} <input file>")
    print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        raise Exception("ERROR: invalid number of parameters")
    with open(sys.argv[1], 'r') as f:
        file_content = f.read()

    #; => \n
    file_content = file_content.replace(";","\n")

    rules=[]
    for line in file_content.splitlines():
        #Ignore emtpy lines, or lines with comments
        line_s = re.sub(r"#.*$", "", line)
        if(re.match(r"^\s*$", line_s)):
            continue

        rule = {}
        matches, actions = extract_tuples(line_s)
        rule["matches"] = matches
        rule["actions"] = actions
        rule["__line__"] = line
        rules.append(rule)

    #print(f"Parsed { len(rules) } rules:")
    #print(f"{json.dumps(rules, indent=2)}")

    print(gen_header(file_content, rules))
