#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .agent_based_api.v1 import (
    all_of,
    startswith,
    exists,
    Metric,
    register,
    Result,
    Service,
    SNMPTree,
    State,
    get_value_store,
    render,
)

def discover_sophos_xgs_lic(section):
    yield Service()

def check_sophos_xgs_lic(section):
    basefw_state = section[0][0]
    basefw_exp = section[0][1]
    network_state = section[0][2]
    network_exp = section[0][3]
    webprot_state = section[0][4]
    webprot_exp = section[0][5]
    email_state = section[0][6]
    email_exp = section[0][7]
    websrv_state = section[0][8]
    websvr_exp = section[0][9]
    zeroday_state = section[0][10]
    zeroday_exp = section[0][11]
    enhprot_state = section[0][12]
    enhprot_exp = section[0][13]
    enhprotplus_state = section[0][14]
    enhprotplus_exp = section[0][15]
    centorch_state = section[0][16]
    centorch_exp = section[0][17]
    

    if s == State.OK:
        summarytext = ""
    else:
        summarytext = ""

    summarydetails = ""

    yield Result(state=s, summary = f"{summarytext}", details = summarydetails)

register.snmp_section(
    name = "sophos_xgs_lic_s",
    detect = startswith(
        ".1.3.6.1.2.1.1.2.0", 
        ".1.3.6.1.4.1.2604.5",
    ),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.2604.5.1.5",
        oids = ["1.1.0", "1.2.0", "2.1.0", "2.2.0", "3.1.0", "3.2.0", "4.1.0", "4.2.0", "5.1.0", "5.2.0", "6.1.0", "6.2.0", "7.1.0", "7.2.0", "8.1.0", "8.2.0", "9.1.0", "9.2.0"],
    ),
)

register.check_plugin(
    name = "sophos_xgs_lic",
    sections = [ "sophos_xgs_lic_s" ],
    service_name = "_Sophos HA Info",
    discovery_function = discover_sophos_xgs_lic,
    check_function = check_sophos_xgs_lic,
)