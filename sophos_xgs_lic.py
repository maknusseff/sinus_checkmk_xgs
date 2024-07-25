#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
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
    websvr_state = section[0][8]
    websvr_exp = section[0][9]
    zeroday_state = section[0][10]
    zeroday_exp = section[0][11]
    enhsup_state = section[0][12]
    enhsup_exp = section[0][13]
    enhplussup_state = section[0][14]
    enhplussup_exp = section[0][15]
    centorch_state = section[0][16]
    centorch_exp = section[0][17]
    
    lic_states = [basefw_state, network_state, webprot_state, email_state, websvr_state, zeroday_state, enhsup_state, enhplussup_state, centorch_state]
    lic_exp = [basefw_exp, network_exp, webprot_exp, email_exp, websvr_exp, zeroday_exp, enhsup_exp, enhplussup_exp, centorch_exp]

    sum1 = "Licence States: "

    c1 = 0

    #s = State.OK

    if "4" in lic_states:
        s = State.CRIT
    elif "4" not in lic_states:
        s = State.OK
    else:
        s = State.WARN

    for e in lic_states:
        c1 += 1
        if e == "0":
            statename ="None"
        elif e == "1":
            statename = "Evaluation"
        elif e == "2":
            statename = "Not Subscribed"
        elif e == "3":
            statename = "Subscribed"
        elif e == "4":
            statename = "Expired"
        elif e == "5":
            statename = "Deactivated"
        else:
            statename = "Unknown"

        if c1 == 1:
            licname = "Base Firewall"
        elif c1 == 2:
            licname = "Network Protection"
        elif c1 == 3:
            licname = "Web Protection"
        elif c1 == 4:
            licname = "Email Protection"
        elif c1 == 5:
            licname = "Web Server Protection"
        elif c1 == 6:
            licname = "Zeroday Protection"
        elif c1 == 7:
            licname = "Enhanced Support"
        elif c1 == 8:
            licname = "Enhanced Plus Support"
        elif c1 == 9:
            licname = "Central Orchestration"
        
        lic_exp_t = lic_exp[c1 - 1]

        now = datetime.datetime.now()
        try:
            lic_exp_d = datetime.datetime.strptime(lic_exp_t, "%b %d %Y")

            lic_delta = lic_exp_d - now
            lic_delta = str(lic_delta).split(" ", 1)[0]
        except:
            continue

        if statename == "Expired":
            statename = statename + " (since " + lic_exp_t + ")"

        if statename == "Subscribed":
            statename = statename + " (" + lic_delta + " days to go)"

        if lic_exp_t == "fail":
            lic_exp_t = "Unknown"

        sum1 = sum1 + "\n" + "----------------------------------------------------------------------------------------------------------" + "\n" + licname + ": " + statename + " >>>>> Exp. date: " + lic_exp_t
  
    if s == State.OK:
        summarytext = "All Licences are fine"
    elif s == State.CRIT:
        summarytext = "Some Licences are expired"
    else:
        summarytext = "Something is wrong with your Licences"

    summarydetails = sum1

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
    service_name = "_Sophos Licence Info",
    discovery_function = discover_sophos_xgs_lic,
    check_function = check_sophos_xgs_lic,
)