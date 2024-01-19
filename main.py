"""
This is the ultimate version, considering Firemon's limiatations.
Module Name: FiremonPandaextractor
creation date: 10/2/2023
Primary Author: Sebastian Brightly
History: (url to sharepoint) (url to UML diagram)
Synopsis: This module was designed to pull from Firemon rules that we are monitoring, based on the controls outlined within the code
These rules are exported to a csv file, first to show the totals without additional information, the second csv prints out the actual rules
using Firemon's ID structure to identify duplicates.


Functions:

Variables:

"""
#Segment start
import FiremonAPIClient
import requests
import json
import csv
from datetime import date
import time
import pandas as pd
import os
import threading
import concurrent.futures
from requests.adapters import HTTPAdapter, Retry

MasterfiremonDF = pd.DataFrame()
TotalcsvDF = pd.DataFrame()
threads = []
childthreads = []

# This function creates the string for querying against SIQL
#Query = rule { (action != 'DROP' AND action != 'REJECT' ) AND (disabled = false) AND (service.any = false AND  (( service intersects 'tcp/21' ) OR ( service intersects 'udp/21' ) OR ( service intersects 'tcp/69' ) OR ( service intersects 'tcp/5985' ) OR ( service intersects 'udp/389' ) OR ( service intersects 'tcp/389' ) OR ( service intersects 'tcp/23' ) OR ( service intersects 'udp/23' ) OR ( service intersects 'tcp/5353' ) OR ( service intersects 'udp/5353' )) ) AND  (ruleName !~ 'k8s' AND ruleName !~ 'gke-' AND ruleName !~ 'acl-' AND rulename != 'intrazone-default' AND rulename != 'interzone-default') AND (p.exception !~ 'riskyport' OR p.exception is null) }
#it should return all secrules excluding acl and rules we aren't concerned about
def HasRiskyPorts(FiremonID):
    x = "/siql/secrule/paged-search?q=rule%20%7B%20id%20%3D%20%27"
    SpliceID = str(FiremonID)
    y = "%27%20%7D%20%20AND%20control%20%7B%20id%20%3D%20%275ac35724-23ab-47a5-9228-a36f1aab76a1%27%7D%20%7C%20fields%28props%29&page=0&pageSize=1"
    z = x + SpliceID + y
    QueryRiskyPort = client.get(method=f'{z}')
    QueryRiskyPortjson = QueryRiskyPort.json()
    IsRiskyPort = QueryRiskyPortjson['total']    
    if IsRiskyPort: #i
        return True
    else:
        return False

# This function creates a string for querying against SIQL
#Query = 
# 
def HasException(FiremonID):
    x = "/siql/secrule/paged-search?q=rule%20%7B%20id%20%3D%20%27"
    SpliceID = str(FiremonID)
    y = "%27%20AND%20p.exception%20is%20not%20null%20%7D%20%7C%20fields%28props%29&page=0&pageSize=1"
    z = x + SpliceID + y
    QueryException = client.get(method=f'{z}')
    QueryExceptionjson = QueryException.json()
    IsException = QueryExceptionjson['total']    
    if IsException: #i
        expText = QueryExceptionjson['results'][0]['props']['exception']
        return expText
    else:
        return False

# This function creates the string for querying against SIQL
#Query = rule {(ruleName !~ 'k8s' AND ruleName !~ 'gke-' AND ruleName !~ 'acl-' AND rulename != 'intrazone-default' AND rulename != 'interzone-default') AND (p.APMID is empty OR p.APMID is null) }
#it should return all secrules excluding acl and missing APMIDs
def MissingAPMIDSecRules(GroupID, pageNum, ed_page):
    head = "/siql/secrule/paged-search?q=devicegroup%20%7B%20id%20%3D%20%27"
    Groupid = str(GroupID)
    body = "%27%20%7D%20AND%20rule%20%7B%28ruleName%20%21~%20%27k8s%27%20AND%20ruleName%20%21~%20%27gke-%27%20AND%20ruleName%20%21~%20%27acl-%27%20AND%20rulename%20%21%3D%20%27intrazone-default%27%20AND%20rulename%20%21%3D%20%27interzone-default%27%29%20%20AND%20%28p.APMID%20is%20empty%20OR%20p.APMID%20is%20null%29%20%7D&page="
    #0&pageSize=1
    PgInx = str(pageNum)
    tail = "&pageSize="
    ed_idx = str(ed_page)
    FullQuery = head + Groupid + body + PgInx + tail + ed_idx
    return FullQuery


def ExceptionRules(GroupID, pageNum, ed_page):
    head = "/siql/secrule/paged-search?q=devicegroup+%7B+id+%3D+"
    Groupid = str(GroupID)
    body = "+%7D++AND+rule+%7B+(redundant+%3D+true)+AND+(ruleName+!~+%27k8s%27+OR+ruleName+!~+%27gke-%27+OR+ruleName+!~+%27acl-%27+OR+ruleName+!%3D+%27intrazone-default%27+OR+ruleName+!%3D+%27interzone-default%27)+AND+p.exception+is+not+null+%7D++%7C+fields(tfacount,+props,+controlstat,+usage(date(%27last+30+days%27)),+change,+highlight)&page="
    #0&pageSize=20&sort=device.name&sort=policy.name&sort=order
    PgInx = str(pageNum)
    tail = "&pageSize="
    ed_idx = str(ed_page)
    FullQuery = head + Groupid + body + PgInx + tail + ed_idx
    return FullQuery

# This function creates the string for querying against SIQL
#Query = rule {(ruleName !~ 'k8s' AND ruleName !~ 'gke-' AND ruleName !~ 'acl-' AND rulename != 'intrazone-default' AND rulename != 'interzone-default') AND (redundant = true) }
#it should return all secrules excluding acl and rules we aren't concerned about    
def RedundantQuery(GroupID, pageNum, ed_page):
    head = "/siql/secrule/paged-search?q=devicegroup+%7B+id+%3D+"
    Groupid = str(GroupID)
    body = "+%7D+AND+rule+%7B(ruleName+!~+%27k8s%27+AND+ruleName+!~+%27gke-%27+AND+ruleName+!~+%27acl-%27+AND+rulename+!%3D+%27intrazone-default%27+AND+rulename+!%3D+%27interzone-default%27)+AND+(redundant+%3D+true)+%7D+%7C+fields(tfacount,+props,+controlstat,+usage(date(%27last+30+days%27)),+change,+highlight)&page="
    #0&pageSize=20&sort=device.name&sort=policy.name&sort=order
    PgInx = str(pageNum)
    tail = "&pageSize="
    ed_idx = str(ed_page)
    FullQuery = head + Groupid + body + PgInx + tail + ed_idx
    return FullQuery


# This function creates the string for querying against SIQL
#Query = rule {(ruleName !~ 'k8s' AND ruleName !~ 'gke-' AND ruleName !~ 'acl-' AND rulename != 'intrazone-default' AND rulename != 'interzone-default') AND (shadow = true) }
#it should return all secrules excluding acl and rules we aren't concerned about 
def ShadowQuery(GroupID, pageNum, ed_page):
    head = "/siql/secrule/paged-search?q=devicegroup+%7B+id+%3D+"
    Groupid = str(GroupID)
    body = "+%7D+AND+rule+%7B(ruleName+!~+%27k8s%27+AND+ruleName+!~+%27gke-%27+AND+ruleName+!~+%27acl-%27+AND+rulename+!%3D+%27intrazone-default%27+AND+rulename+!%3D+%27interzone-default%27)+AND+(shadowed+%3D+true)+%7D+%7C+fields(tfacount,+props,+controlstat,+usage(date(%27last+30+days%27)),+change,+highlight)&page="
    #0&pageSize=20&sort=device.name&sort=policy.name&sort=order
    PgInx = str(pageNum)
    tail = "&pageSize="
    ed_idx = str(ed_page)
    FullQuery = head + Groupid + body + PgInx + tail + ed_idx
    return FullQuery

def RiskyQuery(GroupID, pageNum, ed_page):
    head = "/siql/secrule/paged-search?q=devicegroup+%7B+id+%3D+"
    Groupid = str(GroupID)
    body = "+%7D+AND+rule+%7B+(action+!%3D+%27DROP%27+AND+action+!%3D+%27REJECT%27+)+AND+(disabled+%3D+false)+AND+(service.any+%3D+false+AND++((+service+intersects+%27tcp%2F21%27+)+OR+(+service+intersects+%27udp%2F21%27+)+OR+(+service+intersects+%27tcp%2F69%27+)+OR+(+service+intersects+%27tcp%2F5985%27+)+OR+(+service+intersects+%27udp%2F389%27+)+OR+(+service+intersects+%27tcp%2F389%27+)+OR+(+service+intersects+%27tcp%2F23%27+)+OR+(+service+intersects+%27udp%2F23%27+)+OR+(+service+intersects+%27tcp%2F5353%27+)+OR+(+service+intersects+%27udp%2F5353%27+))+)+AND++(ruleName+!~+%27k8s%27+AND+ruleName+!~+%27gke-%27+AND+ruleName+!~+%27acl-%27+AND+rulename+!%3D+%27intrazone-default%27+AND+rulename+!%3D+%27interzone-default%27)+AND+(p.exception+!~+%27riskyport%27+OR+p.exception+is+null)+%7D+%7C+fields(tfacount,+props,+controlstat,+usage(date(%27last+30+days%27)),+change,+highlight)&page="
    PgInx = str(pageNum)
    #&pageSize=  20&sort=device.name&sort=policy.name&sort=order
    tail = "&pageSize="
    ed_idx = str(ed_page)
    FullQuery = head + Groupid + body + PgInx + tail + ed_idx
    return FullQuery


#Segment stop
#Segment start


def String_call(GroupID, pageNum, ed_page):
    head = "/siql/secrule/paged-search?q=devicegroup%7B%20id%20%3D%20"
    Groupid = str(GroupID)
    body = "%7D%20%20AND%20rule%20%7B%28ruleName%20%21~%20%27k8s%27%20AND%20ruleName%20%21~%20%27gke-%27%20AND%20ruleName%20%21~%20%27acl-%27%20AND%20rulename%20%21%3D%20%27intrazone-default%27%20AND%20rulename%20%21%3D%20%27interzone-default%27%29%20%7D%20%7C%20fields%28props%29&page="
    PgInx = str(pageNum)
    tail = "&pageSize="
    ed_idx = str(ed_page)
    FullQuery = head + Groupid + body + PgInx + tail + ed_idx
    return FullQuery

def Json_return(GroupID, pageNum, end_idx,CurrentGroupNAME):
    print(f"Thread started {CurrentGroupNAME}")
    TimeOutCount = 0
    client = FiremonAPIClient.Client()
    client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")
    query = String_call(GroupID, pageNum, 1)
    RiskyPQ = RiskyQuery(GroupID, pageNum, 1)
    ShadowQ = ShadowQuery(GroupID, pageNum, 1)
    RedundantQ = RedundantQuery(GroupID, pageNum, 1)
    ExceptionQ = ExceptionRules(GroupID, pageNum, 1)
    MAPMIDQ = MissingAPMIDSecRules(GroupID, pageNum, 1)
    #print(query)
    FSecRulesdevicegroups = client.get(method=f'{query}')
    RiskyPQs = client.get(method=f'{RiskyPQ}')
    ShadowQs = client.get(method=f'{ShadowQ}')
    RedundantQs = client.get(method=f'{RedundantQ}')
    ExceptionQs = client.get(method=f'{ExceptionQ}')
    MAPMIDQs = client.get(method=f'{MAPMIDQ}')

    FSecRulesjson = FSecRulesdevicegroups.json()
    RiskyPQsjson = RiskyPQs.json()
    ShadowQsjson = ShadowQs.json()
    RedundantQsjson = RedundantQs.json()
    ExceptionQsjson = ExceptionQs.json()
    MAPMIDQsjson = MAPMIDQs.json()
    TotalsaddDFpage(CurrentGroupNAME,GroupID,FSecRulesjson,RiskyPQsjson,ShadowQsjson,RedundantQsjson,ExceptionQsjson,MAPMIDQsjson)

    print("The Device Group:", CurrentGroupNAME)
    print("The Device Group ID:", GroupID)
    print("Total filtered SecRules:", FSecRulesjson['total'])
    print("Total Risky Ports:", RiskyPQsjson['total'])
    print("Total Missing APMID SecRules:", MAPMIDQsjson['total'])
    print("Total redundant SecRules", RedundantQsjson['total'])
    print("Total Shadow SecRules", ShadowQsjson['total'])
    print("Total Exception SecRules", ExceptionQsjson['total'])
    QueryRules(GroupID,CurrentGroupNAME,RiskyPQsjson['total'],MAPMIDQsjson['total'],RedundantQsjson['total'],ShadowQsjson['total'],ExceptionQsjson['total'])
    client.disconnect()
    print(f"Thread ended {CurrentGroupNAME}")
#Segment stop
#Segment start
def QueryRules(GroupID,CurrentGroupNAME,RiskyPQsjsontotal,MAPMIDQsjsontotal,RedundantQsjsontotal,ShadowQsjsontotal,ExceptionQsjsontotal):
    client = FiremonAPIClient.Client()
    client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")

    RiskyLC = 0
    while RiskyLC < RiskyPQsjsontotal:
        RiskySingles = RiskyQuery(GroupID, RiskyLC, 1)
        RiskySgl = client.get(method=f'{RiskySingles}')
        RiskySgljson = RiskySgl.json()
        ruletype = "Risky Ports"
        addrulePages(GroupID,CurrentGroupNAME,RiskySgljson,ruletype)
        RiskyLC += 1
    
    client.disconnect()
    client = FiremonAPIClient.Client()
    client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")

    APMIDLC = 0
    while APMIDLC < MAPMIDQsjsontotal:
        APMIDSingles = MissingAPMIDSecRules(GroupID, APMIDLC, 1)
        APMIDSgl = client.get(method=f'{APMIDSingles}')
        APMIDSgljson = APMIDSgl.json()
        ruletype = "APMID Missing"
        addrulePages(GroupID,CurrentGroupNAME,APMIDSgljson,ruletype)
        APMIDLC += 1

    client.disconnect()
    client = FiremonAPIClient.Client()
    client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")
    
    RedLC = 0
    while RedLC < RedundantQsjsontotal:
        RedSingles = RedundantQuery(GroupID, RedLC, 1)
        RedSgl = client.get(method=f'{RedSingles}')
        RedSgljson = RedSgl.json()
        ruletype = "Redundant"
        addrulePages(GroupID,CurrentGroupNAME,RedSgljson,ruletype)
        RedLC += 1       
    client.disconnect()
    client = FiremonAPIClient.Client()
    client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")

    ShadowLC = 0
    while ShadowLC < ShadowQsjsontotal:
        ShadowSingles = ShadowQuery(GroupID, ShadowLC, 1)
        ShadowSgl = client.get(method=f'{ShadowSingles}')
        ShadowSgljson = ShadowSgl.json()
        ruletype = "Shadow"
        addrulePages(GroupID,CurrentGroupNAME,ShadowSgljson,ruletype)
        ShadowLC += 1       

    client.disconnect()
    client = FiremonAPIClient.Client()
    client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")

    ExpLC = 0
    while ExpLC < ExceptionQsjsontotal:
        ExpSingles = ExceptionRules(GroupID, ExpLC, 1)
        ExpSgl = client.get(method=f'{ExpSingles}')
        ExpSgljson = ExpSgl.json()
        ruletype = "Except"
        addrulePages(GroupID,CurrentGroupNAME,ExpSgljson,ruletype)
        ExpLC += 1   

    client.disconnect()

#Segment stop
#Segment start
#still in progress
def addrulePages(GroupID,CurrentGroupNAME,JsonObject,ruletype):
    global MasterfiremonDF
    #FiremonID = JsonObject['results'][0]['matchId']
    #print(JsonObject)
    #if not MasterfiremonDF[(MasterfiremonDF['FiremonID'] == FiremonID)].empty:
    try:
        firemon1= pd.DataFrame({"Groupname":[CurrentGroupNAME],
                        "GroupID":[GroupID],
                        "SecRuleName":[JsonObject['results'][0]['name']],
                        "SecRuleDisplayName":[JsonObject['results'][0]['displayName']],
                        "FiremonID":[JsonObject['results'][0]['matchId']],
                        "ShadowedLabel":[JsonObject['results'][0]['redundant']],
                        "RedundantLabel":[JsonObject['results'][0]['shadowed']],
                        "ruletype":[ruletype],
                        "APMID":[''],
                        "RiskyPort":[''],
                        "Exceptions":['']
                        })
    except KeyError:
        print(JsonObject, file=sys.stderr)
        with open('C:\\Users\\sebastian.brightly\\Documents\\Log.txt','a') as file:
            print(JsonObject, file=file)
    
    try:
        firemon1.APMID = JsonObject['results'][0]['props']['APMID']
    except KeyError:
        firemon1.APMID = "NaN"

    try:
        FiremonID = JsonObject['results'][0]['matchId']
        RiskyResult = HasRiskyPorts(FiremonID)
        firemon1.RiskyPort = RiskyResult
    except:
        firemon1.RiskyPort = "NaN"

    try:
        FiremonID = JsonObject['results'][0]['matchId']
        HasException = HasException(FiremonID)
        firemon1.Exceptions = HasException
    except:
        firemon1.Exceptions = "NaN"


    MasterfiremonDF = MasterfiremonDF._append(firemon1, ignore_index = True)



def TotalsaddDFpage(CurrentGroupNAME,GroupID,FSecRulesjson,RiskyPQsjson,ShadowQsjson,RedundantQsjson,ExceptionQsjson,MAPMIDQsjson):
    global TotalcsvDF
    firemon1= pd.DataFrame({"Groupname":[CurrentGroupNAME],
                    "GroupID":[GroupID],
                    "Total Rules":[FSecRulesjson['total']],
                    "Total Missing APMID":[MAPMIDQsjson['total']],
                    "Total Redundant Rules":[RedundantQsjson['total']],
                    "Total Shadowed Rules":[ShadowQsjson['total']],
                    "Total Rules with Risky Ports":[RiskyPQsjson['total']],
                    "Total Rules with Exceptions":[ExceptionQsjson['total']]
                    })

    TotalcsvDF = TotalcsvDF._append(firemon1, ignore_index = True)


#initate a connection to Firemon, This should be the first connection it makes to the server
#The log in credentials can be changed, but as it is designed now, you would need to change it for each connection call
client = FiremonAPIClient.Client()
client.connect(url='https://firemon.cardinalhealth.net', username="firemon", password="Ass!st@nc3R3qu!r3d")
CurrentGroupID = 0
#SJB 9/25/2023 ##This initial query will request that the device groups be returned
#SJB 9/25/2023 ##following Firemon's standard json return
Query_devicegroups = client.get(method=f'/siql/devicegroup/paged-search?q=domain%7Bid%3D1%7D&page=0&pageSize=50&sortdir=asc&sort=name')
#SJB 9/25/2023 ##This will convert the returned result into a workable python dictionary
Query_DGjson = Query_devicegroups.json()
Device_Group_count = Query_DGjson['total']
#SJB 9/25/2023 ##This variable is used to track the loops within the device groups, this can later be changed to a len() of ['results'] incase we end up creating more groups in the future
DGcount = 0
#SJB 9/25/2023 ##From experience, Firemon has a time limit of how long a connection can stay active before it starts to return errors, so reinitializing thses connections becomes necessary
client.disconnect()

while DGcount < Device_Group_count:
    if Query_DGjson['results'][DGcount]['name'] != "All Devices" and Query_DGjson['results'][DGcount]['name'] != "Dublin Panorama" and Query_DGjson['results'][DGcount]['name'] != "GCP Palo Alto Firewalls":
        CurrentGroupID = Query_DGjson['results'][DGcount]['id']
        CurrentGroupNAME = Query_DGjson['results'][DGcount]['name']
        #to do, change this to a loging output so it isn't displaying this in out stream unless we deem it necessary
        print("DGcount :", DGcount)
        print("The Device Group:", CurrentGroupNAME)
        print("The Device Group ID:", CurrentGroupID)
        
        #SJB 9/25/2023 #To compensate for the amount of time it takes for firemon to iterate through query requests, I had to create threads that break the work up between the device groups
        #SJB 9/25/2023 #This can be further divided with child threads, but I was not currently aware of connection limitations that exist in firemon
        thread = threading.Thread(target=Json_return, args=(CurrentGroupID,0,1,CurrentGroupNAME,))
        threads.append(thread)
        thread.start()
        if DGcount == 11:
            print(TotalcsvDF)
    DGcount += 1
    
for thread in threads:
    thread.join()

#SJB 9/25/2023 #This print can be changed to a loging statement, it was only used during debuging to show that the dataframes were populating correctly
print(TotalcsvDF)
#SJB 9/25/2023 # This is the results being exported to a cvs file, noting the time it was taken by year, month, day and hour of the day
#SJB 9/25/2023 # 
timestr = time.strftime("%Y%m%d-%H")
filename = 'C:\\Users\\sebastian.brightly\\Documents\\FiremonDF' + timestr + '.csv'
TotalcsvDF.to_csv(filename)

#SJB 9/25/2023 #
timestr = time.strftime("%Y%m%d-%H")
filename2 = 'C:\\Users\\sebastian.brightly\\Documents\\FiremonSingleRules' + timestr + '.csv'
MasterfiremonDF.to_csv(filename2)

#Segment End
