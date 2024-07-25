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

def parse_sophos(string_table):
    global result
    #print(string_table)
    result = {}
    result["clustername"] = string_table[0][0]
    result["devicetype"] = string_table[0][1]
    result["firmware"] = string_table[0][2]
    result["serialnumber"] = string_table[0][3]
    #print(result)
    return result

def discover_sophos_xgs_version(section):
    yield Service()

def check_sophos_xgs_version(section):
    clustername = result["clustername"]
    devicetype = result["devicetype"]
    firmware = result["firmware"]
    serialnumber = result["serialnumber"]

    s = State.OK

    if clustername != "":
        s = State.OK
    else:
        s = State.CRIT

    if s == State.OK:
        summarytext = "Clustername: " + clustername + "   |   Firmware: " + firmware
        
    else:
        summarytext = "CRIT"

    summarydetails = "Clustername: " + clustername + "\n" + "Devicetype: " + devicetype + "\n" + "Firmware: " + firmware + "\n" + "Serialnumber: " + serialnumber + " (current active member)"

    yield Result(state=s, summary = f"{summarytext}", details = summarydetails)

register.snmp_section(
    name = "sophos_xgs_general_s",
    parse_function = parse_sophos,
    detect = startswith(
        ".1.3.6.1.2.1.1.2.0", 
        ".1.3.6.1.4.1.2604.5",
    ),
    fetch = SNMPTree(
        base = ".1.3.6.1.4.1.2604.5.1.1",
        oids = ["1.0", "2.0", "3.0", "4.0"],
    ),
)

register.check_plugin(
    name = "sophos_xgs_general",
    sections = [ "sophos_xgs_general_s" ],
    service_name = "_Sophos Device Info",
    discovery_function = discover_sophos_xgs_version,
    check_function = check_sophos_xgs_version,
)