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

def discover_sophos_xgs_ha(section):
    yield Service()

def check_sophos_xgs_ha(section):
    hastate = section[0][0]
    serial_devone = section[0][1]
    serial_devtwo = section[0][2]
    state_devone = section[0][3]
    state_devtwo = section[0][4]
    clustertype = section[0][5]
    clusterport = section[0][7]
    ip_devone = section[0][8]
    ip_devtwo = section[0][9]

    if hastate == "1":
        hastatename = "enabled"
        s = State.OK
    else:
        hastatename = "disabled / error"
        s = State.CRIT

    if state_devone == "0":
        state_devone_name = "Not Applicable"
    if state_devone == "1":
        state_devone_name = "Auxiliary"
    if state_devone == "2":
        state_devone_name = "Standalone"
    if state_devone == "3":
        state_devone_name = "Primary"
    if state_devone == "4":
        state_devone_name = "Faulty"
    if state_devone == "5":
        state_devone_name = "Ready"

    if state_devtwo == "0":
        state_devtwo_name = "Not Applicable"
    if state_devtwo == "1":
        state_devtwo_name = "Auxiliary"
    if state_devtwo == "2":
        state_devtwo_name = "Standalone"
    if state_devtwo == "3":
        state_devtwo_name = "Primary"
    if state_devtwo == "4":
        state_devtwo_name = "Faulty"
    if state_devtwo == "5":
        state_devtwo_name = "Ready"
    

    if s == State.OK:
        summarytext = "HA is configured and working fine"
    else:
        summarytext = "Something is wrong with the HA configuration"

    summarydetails = "HA State: " + hastatename + "\n" + "---------------------------------" + "\n" + "SN device 1: " + serial_devone + "\n" + "IP devone: " + ip_devone  + "\n" + "State device 1: " + state_devone_name + "\n\n" + "SN device 2: " + serial_devtwo + "\n" + "IP devtwo: " + ip_devtwo + "\n" + "State device 2: " + state_devtwo_name + "\n" + "---------------------------------" + "\n" + "Cluster Type: " + clustertype + "\n" + "HA Port: " + clusterport

    yield Result(state=s, summary = f"{summarytext}", details = summarydetails)

register.snmp_section(
    name = "sophos_xgs_ha_s",
    detect = startswith(
        ".1.3.6.1.2.1.1.2.0", 
        ".1.3.6.1.4.1.2604.5",
    ),
    fetch=SNMPTree(
        base=".1.3.6.1.4.1.2604.5.1.4",
        oids = ["1.0", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "8.0","9.0","10.0"],
    ),
)

register.check_plugin(
    name = "sophos_xgs_ha",
    sections = [ "sophos_xgs_ha_s" ],
    service_name = "_Sophos HA Info",
    discovery_function = discover_sophos_xgs_ha,
    check_function = check_sophos_xgs_ha,
)