import logging
import xml.etree.ElementTree as ET
import json
import time

import maltoolbox
from maltoolbox.language import classes_factory
from maltoolbox import attackgraph
from maltoolbox import model as malmodel
from maltoolbox.ingestors import neo4j
from maltoolbox.language import LanguageGraph, LanguageClassesFactory
from maltoolbox.model import Model, AttackerAttachment
from maltoolbox.attackgraph.analyzers import apriori
from maltoolbox.wrappers import create_attack_graph
from maltoolbox.attackgraph import AttackGraph, query

logger = logging.getLogger(__name__)

#------------------LANGUAGE FILES-----------------
#The sasLang language file
lang_file = 'sasLang'
lang_graph = LanguageGraph.from_mar_archive(lang_file) 
lang_classes_factory = LanguageClassesFactory(lang_graph)

#Creating an empty instance model
instance_model = Model('SAS Example Model', lang_classes_factory)

#------------------SCD FILES------------------
#Update the scd file below
tree = ET.parse('your_scd_file.scd')
root = tree.getroot()

#Create dictionary of IEDHardwares
IEDHardwares = {}
#Create dictionary of IED OS
IEDOS = {}
#Create dictionary of LDs
LDs = {}
#Create dictionary of Servers
Servers = {}
#Create dictionary of APs
APs = {}

#------------------Communication section of the SCD file-----------------
for subNetwork in root.iter('{http://www.iec.ch/61850/2003/SCL}SubNetwork'):
    subNetAsset = lang_classes_factory.ns.SubNetwork(name = subNetwork.attrib['name'])
    instance_model.add_asset(subNetAsset)
    for accessPoint in subNetwork.iter('{http://www.iec.ch/61850/2003/SCL}ConnectedAP'):
        #Create and add assets to the model
        aPAsset = lang_classes_factory.ns.AccessPoint(name = accessPoint.attrib['apName'])
        instance_model.add_asset(aPAsset)
        APs[accessPoint.attrib['apName']] = aPAsset
        instance_model.add_asset(subNetAsset)
        #The IED has not been created already
        if (not (accessPoint.attrib['iedName'] in IEDHardwares)):
            iedAsset = lang_classes_factory.ns.IEDHardware(name = accessPoint.attrib['iedName'])
            instance_model.add_asset(iedAsset)
            iedOSAppAsset = lang_classes_factory.ns.IcsApplication(name = accessPoint.attrib['iedName']+" OS")
            instance_model.add_asset(iedOSAppAsset)
            #Adding IED to IEDOS
            ied_iedOS_assoc = lang_classes_factory.ns.SysExecution(
            hostHardware = [iedAsset], sysExecutedApps = [iedOSAppAsset])
            instance_model.add_association(ied_iedOS_assoc)
        #THe IED was already created (It communicates on multiple APs)
        else:
            #Pick out the already created assets
            iedAsset = IEDHardwares[accessPoint.attrib['iedName']]
            iedOSAppAsset = IEDOS[accessPoint.attrib['iedName']]

        #Create associations between assets
        ap_iedOS_assoc = lang_classes_factory.ns.ApplicationConnection(
            appConnections = [aPAsset], applications = [iedOSAppAsset])
        subnet_ap_assoc = lang_classes_factory.ns.NetworkConnection(
            networks = [subNetAsset], netConnections = [aPAsset])
        
        #Add the associations to the model
        instance_model.add_association(ap_iedOS_assoc)
        instance_model.add_association(subnet_ap_assoc)
        
        #create a dictionary of the IED Hardware with string, we can use these to create 
        #IED Hardware to connect to the LDs
        IEDHardwares[accessPoint.attrib['iedName']] = iedAsset
        #IED OS dictionnary
        IEDOS[accessPoint.attrib['iedName']] = iedOSAppAsset
#----------------------------------------------------------------------------

#------------------Substation section of the SCD file-----------------
for substatTree in root.iter('{http://www.iec.ch/61850/2003/SCL}Substation'):
    #Create and add substations to the model
    substatAsset = lang_classes_factory.ns.Substation(name = substatTree.attrib['name'])
    instance_model.add_asset(substatAsset)
    #Finds PowerTransformers on substation and bay level
    for ptIter in substatTree.iter('{http://www.iec.ch/61850/2003/SCL}PowerTransformer'):
        ptAsset = lang_classes_factory.ns.Transformer(name = ptIter.attrib['name'])
        instance_model.add_asset(ptAsset)
        #add transformer to substation association
        trans_substat_assoc = lang_classes_factory.ns.SubstatIncludesEq(
        substation = [substatAsset], equipment = [ptAsset])  
        instance_model.add_association(trans_substat_assoc)
    #Create all LNs that exist on substation level (For HMI etc)
    for lnFindAll in substatTree.findall('{http://www.iec.ch/61850/2003/SCL}LNode'):  
        #LLN0 does not have an lnInst, in this case we set the value as "0"  
        if (lnFindAll.attrib['lnClass'] == "LLN0"):
            lnInstance = "0"
        else:
            lnInstance = lnFindAll.attrib['lnInst']
        lnAsset = lang_classes_factory.ns.LogicalNode(name = lnFindAll.attrib['lnClass']+"_"+ lnFindAll.attrib['ldInst']+"_"+lnInstance)
        instance_model.add_asset(lnAsset)
        #add LN to substation association
        ln_substat_assoc = lang_classes_factory.ns.SubstatLevelLN(
        substation = [substatAsset], logicalNode = [lnAsset])  
        instance_model.add_association(ln_substat_assoc)
        #Create a dictionary of LogicalDevices to avoid duplicates. Multiple LNs can exist in the same LD. 
        if (lnFindAll.attrib['iedName']+ "_"+lnFindAll.attrib['ldInst'] in LDs):
            #Add association between LN and LD
            #dont add the LD again but find it and associate to it.
            ln_ld_assoc = lang_classes_factory.ns.AppExecution(
            hostApp = [LDs[lnFindAll.attrib['iedName']+ "_"+lnFindAll.attrib['ldInst']]], appExecutedApps = [lnAsset])
            instance_model.add_association(ln_ld_assoc)
        else:     
            #Create the LD asset and add it to the dictionnary
            ldAsset = lang_classes_factory.ns.LogicalDevice(name = (lnFindAll.attrib['iedName']+ "_"+lnFindAll.attrib['ldInst']))
            instance_model.add_asset(ldAsset)
            LDs[(lnFindAll.attrib['iedName']+ "_"+lnFindAll.attrib['ldInst'])] = ldAsset
            #Add association between LN and LD
            ln_ld_assoc = lang_classes_factory.ns.AppExecution(
                hostApp = [ldAsset], appExecutedApps = [lnAsset])
            instance_model.add_association(ln_ld_assoc)

    #Voltagelevels
    for vlTree in root.iter('{http://www.iec.ch/61850/2003/SCL}VoltageLevel'):
        #Create the Voltage Level asset and add it to the model
        vlAsset = lang_classes_factory.ns.VoltageLevel(name = vlTree.attrib['name'])
        instance_model.add_asset(vlAsset)

        #Connect all voltage levels to the substation
        vl_substat_assoc = lang_classes_factory.ns.SubstatIncludesVL(
            voltageLevel = [vlAsset], substation = [substatAsset])  
        instance_model.add_association(vl_substat_assoc)

        #Bay
        for bayTree in vlTree.iter('{http://www.iec.ch/61850/2003/SCL}Bay'):
            #Create the bay and add it to the model
            bayAsset = lang_classes_factory.ns.Bay(name = bayTree.attrib['name'])
            instance_model.add_asset(bayAsset)

            #Connect all bays to voltagelevels
            bay_vl_assoc = lang_classes_factory.ns.VLIncludesBay(
                bay = [bayAsset], voltageLevel = [vlAsset])
            instance_model.add_association(bay_vl_assoc)

            #--------All LNodes on bay level-----------
            for lnIter in bayTree.findall('{http://www.iec.ch/61850/2003/SCL}LNode'):
                #LLN0 does not have an lnInst, in this case we set the value as "0"  
                if (lnIter.attrib['lnClass'] == "LLN0"):
                    lnInstance = "0"
                else:
                    lnInstance = lnIter.attrib['lnInst']
                lnAsset = lang_classes_factory.ns.LogicalNode(name = lnIter.attrib['lnClass']+"_"+lnIter.attrib['ldInst']+"_"+lnInstance)
        
                instance_model.add_asset(lnAsset)
                ln_bay_assoc = lang_classes_factory.ns.BayLevelLN(
                    logicalNode = [lnAsset], bay = [bayAsset]
                )
                instance_model.add_association(ln_bay_assoc)
                #If the LD has already been created, add the assoc between LN and LD.
                if (lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst'] in LDs):
                    #Add association between LN and LD
                    ln_ld_assoc = lang_classes_factory.ns.AppExecution(
                    hostApp = [LDs[lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst']]], appExecutedApps = [lnAsset])
                    instance_model.add_association(ln_ld_assoc)
                else:     
                    #Create the LD asset and add it to the dictionnary
                    ldAsset = lang_classes_factory.ns.LogicalDevice(name = (lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst']))
                    instance_model.add_asset(ldAsset)
                    LDs[(lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst'])] = ldAsset
                    #Add association between LN and LD
                    ln_ld_assoc = lang_classes_factory.ns.AppExecution(
                        hostApp = [ldAsset], appExecutedApps = [lnAsset])
                    instance_model.add_association(ln_ld_assoc)
                if (lnIter.attrib['iedName'] != "None"):
                    #If the server has already been created we connect the LD to the existing server.
                    if not ("Server_"+lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst'] in Servers):
                        serverAsset = lang_classes_factory.ns.Server(name = "Server_"+lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst'])
                        instance_model.add_asset(serverAsset)
                        Servers["Server_"+lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst']] = serverAsset
                        #Connect the server to the IED
                        #We already have a list of IEDHardwares created in the Subnetwork section, so we pick it out
                        serv_iedHardware_assoc = lang_classes_factory.ns.SysExecution(
                        sysExecutedApps = [serverAsset], hostHardware = [IEDHardwares[lnIter.attrib['iedName']]])
                        #Connect the Server to the LD
                        ld_serv_assoc = lang_classes_factory.ns.AppExecution(
                        hostApp = [LDs[lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst']]], appExecutedApps = [serverAsset]) 
                        #Connect the LN to the newly created LD (server)
                        #ln_ld_assoc = lang_classes_factory.ns.AppExecution(
                        #hostApp = [LDs[lnIter.attrib['iedName']+ "_"+lnIter.attrib['ldInst']]], appExecutedApps = [lnAsset])
                        #instance_model.add_association(ln_ld_assoc)
                        instance_model.add_association(serv_iedHardware_assoc)
                        instance_model.add_association(ld_serv_assoc)

            #-----------------------------------------
            #All conducting equipment for each bay
            for conEq in bayTree.iter('{http://www.iec.ch/61850/2003/SCL}ConductingEquipment'):
                #---------------Circuit breaker-------------------
                if conEq.attrib['type'] == "CBR":
                    #print("   circuitBreaker: " + conEq.attrib['name'])
                    eqAsset = lang_classes_factory.ns.CircuitBreaker(name = conEq.attrib['name'])
                    #Add the equipment to the model
                    instance_model.add_asset(eqAsset)
                    #For Circuit breakers, add a ActuatorCB
                    actCBAsset = lang_classes_factory.ns.ActuatorCB(name = 'CB Actuator')
                    instance_model.add_asset(actCBAsset)
                    act_cb_assoc = lang_classes_factory.ns.CloseOrTrip(
                    actuatorCB = [actCBAsset], circuitBreaker = [eqAsset])
                    instance_model.add_association(act_cb_assoc)
                #---------------Transformer-------------------
                elif conEq.attrib['type'] == "VTR":
                    print("   transformer: " + conEq.attrib['name'])
                    eqAsset = lang_classes_factory.ns.Transformer(name = conEq.attrib['name'])
                    #Add the equipment to the model
                    instance_model.add_asset(eqAsset)
                #---------------Other equipment-------------------
                else:
                    #print("   conductingEquipment: "+conEq.attrib['name'], conEq.attrib['type'])
                    eqAsset = lang_classes_factory.ns.Equipment(name = conEq.attrib['name'])
                    #Add the equipment to the model
                    instance_model.add_asset(eqAsset)
                #-----------------Add logical Nodes part---------------
                #Connect equipment to Bay
                bay_eq_assoc = lang_classes_factory.ns.BayIncludesEq(
                    bay = [bayAsset], equipment = [eqAsset])
                instance_model.add_association(bay_eq_assoc)
                #add the connections of the logicalNodes
                for lnTree in conEq.iter('{http://www.iec.ch/61850/2003/SCL}LNode'):
                    #Equipment is represented by LogicalNodes, connect them to the LNs
                    #Special case is Circuitbreakers, these LNs are connected to the Actuator not the Eq.
                    if lnTree.attrib['lnClass'] == "XCBR":
                        lnAsset = lang_classes_factory.ns.LogicalNode(name = lnTree.attrib['lnClass'] +"_"+lnTree.attrib['ldInst']+"_"+lnTree.attrib['lnInst'])
                        instance_model.add_asset(lnAsset)
                        startingPoint = lnAsset
                        ln_act_assoc = lang_classes_factory.ns.ActRepresent(
                            actuator = [actCBAsset], logicalNode = [lnAsset])
                        instance_model.add_association(ln_act_assoc)
                    else:                      
                        lnAsset = lang_classes_factory.ns.LogicalNode(name = lnTree.attrib['lnClass'] +"_"+lnTree.attrib['ldInst']+"_"+lnTree.attrib['lnInst']) 
                        instance_model.add_asset(lnAsset)
                        ln_eq_assoc = lang_classes_factory.ns.EqRepresent(
                            equipment = [eqAsset], logicalNode = [lnAsset])
                        instance_model.add_association(ln_eq_assoc)
                    #If the LD already exists
                    if ((lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst']) in LDs):   
                        #Dont add it again but connect the LN to LD.
                        ln_ld_assoc = lang_classes_factory.ns.AppExecution(
                        hostApp = [LDs[lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst']]], appExecutedApps = [lnAsset])
                        instance_model.add_association(ln_ld_assoc)
                    #Else we need to create the LD
                    else:    
                        #Create the LD asset and connect LN+LD
                        ldAsset = lang_classes_factory.ns.LogicalDevice(name = (lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst']))
                        instance_model.add_asset(ldAsset)
                        LDs[(lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst'])] = ldAsset
                        ln_ld_assoc = lang_classes_factory.ns.AppExecution(
                            hostApp = [ldAsset], appExecutedApps = [lnAsset])
                        instance_model.add_association(ln_ld_assoc)
                        
                    #If the logicalNode is hosted on an IED, then connect the Server to the IEDHardware (and LN to LD)
                    if (lnTree.attrib['iedName'] != "None"):
                        #Create a server asset but check we didnt already have it. If server exist we aready connected it to IED.
                        if not ("Server_"+lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst'] in Servers):
                            serverAsset = lang_classes_factory.ns.Server(name = "Server_"+lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst'])
                            instance_model.add_asset(serverAsset)
                            Servers["Server_"+lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst']] = serverAsset                  
                            #Connect the server to the IED
                            #We already have a list of IEDHardwares created in the Subnetwork section, so we pick it out
                            serv_iedHardware_assoc = lang_classes_factory.ns.SysExecution(
                            sysExecutedApps = [serverAsset], hostHardware = [IEDHardwares[lnTree.attrib['iedName']]])
                            #Connect the Server to the LD
                            ld_serv_assoc = lang_classes_factory.ns.AppExecution(
                            hostApp = [LDs[lnTree.attrib['iedName']+ "_"+lnTree.attrib['ldInst']]], appExecutedApps = [serverAsset])  
                            instance_model.add_association(serv_iedHardware_assoc)
                            instance_model.add_association(ld_serv_assoc)    
                    else:
                        #otherwise connect the LN to the AP directly (Client AP) and add it to the bay
                        ln_ap_assoc = lang_classes_factory.ns.ApplicationConnection(
                            appConnections = [aPAsset], applications = [lnAsset])
                        instance_model.add_association(ln_ap_assoc)

#------------------------------------------------------------------------------------------
#------------------IED section of the SCD file-----------------
#For all the IEDs in this section, create LNs
for iedIter in root.iter('{http://www.iec.ch/61850/2003/SCL}IED'):
    #Retrieving the correct IED OS asset
    for iedAPfindall in iedIter.findall('{http://www.iec.ch/61850/2003/SCL}AccessPoint'):
        #Check for the special case that an LN is connected directly to an IED without an LD.
        #These LNs are straight under the AP without a server or LD.
        for APLNfindall in iedAPfindall.findall('{http://www.iec.ch/61850/2003/SCL}LN'):
            #Create the new LN
            lnAsset = lang_classes_factory.ns.LogicalNode(name = APLNfindall.attrib['lnClass']+"_None_"+APLNfindall.attrib['inst'])
            instance_model.add_asset(lnAsset)
            #Associate the new LN to the previously defined IED directly.
            #Adding LN to prev defined IED
            ied_ln_assoc = lang_classes_factory.ns.SysExecution(
            hostHardware = [IEDHardwares[iedIter.attrib['name']]], sysExecutedApps = [lnAsset])
            instance_model.add_association(ied_ln_assoc)
            #Connect LN to AP
            if (iedAPfindall.attrib['name'] in APs):
                ln_ap_assoc = lang_classes_factory.ns.ApplicationConnection(
                    appConnections = [APs[iedAPfindall.attrib['name']]], applications = [lnAsset])
                instance_model.add_association(ln_ap_assoc)
            else: 
                aPAsset = lang_classes_factory.ns.AccessPoint(name = iedAPfindall.attrib['name'])
                instance_model.add_asset(aPAsset)
                APs[accessPoint.attrib['apName']] = aPAsset
                ln_ap_assoc = lang_classes_factory.ns.ApplicationConnection(
                    appConnections = [aPAsset], applications = [lnAsset])
                instance_model.add_association(ln_ap_assoc)
    for LDeviceIter in iedIter.iter('{http://www.iec.ch/61850/2003/SCL}LDevice'):
        #Create LD
        ldAsset = lang_classes_factory.ns.LogicalDevice(name = (iedIter.attrib['name']+ "_"+LDeviceIter.attrib['inst']))
        instance_model.add_asset(ldAsset)
        #Create server
        serverAsset = lang_classes_factory.ns.Server(name = "Server")
        instance_model.add_asset(serverAsset)
        #Connect LD to Server
        ld_server_assoc = lang_classes_factory.ns.AppExecution(
            hostApp = [serverAsset], appExecutedApps = [ldAsset])
        instance_model.add_association(ld_server_assoc)
        #Connect Server to IED
        ied_server_assoc = lang_classes_factory.ns.SysExecution(
            hostHardware = [IEDHardwares[iedIter.attrib['name']]], sysExecutedApps = [serverAsset])
        instance_model.add_association(ied_server_assoc)
        for LNfindAll in LDeviceIter.findall('{http://www.iec.ch/61850/2003/SCL}LN'):
            lnAsset = lang_classes_factory.ns.LogicalNode(name = LNfindAll.attrib['lnClass']+"_"+LDeviceIter.attrib['inst']+"_"+LNfindAll.attrib['inst'])
            instance_model.add_asset(lnAsset)
            #Adding data packages manually
            #if (LNfindAll.attrib['lnClass']+"_"+LDeviceIter.attrib['inst']+"_"+LNfindAll.attrib['inst'] == "CILO_LD0_1"):
            #    EnaOpnAsset = lang_classes_factory.ns.IcsData(name = "EnaOpn")
            #    EnaClsAsset = lang_classes_factory.ns.IcsData(name = "EnaCls")
            #    instance_model.add_asset(EnaOpnAsset)
            #    instance_model.add_asset(EnaClsAsset)
            #    enaOpn_ln_assoc = lang_classes_factory.ns.SendData(sentData = [EnaOpnAsset], senderApp = [lnAsset])
            #    instance_model.add_association(enaOpn_ln_assoc)
            #    enaCls_ln_assoc = lang_classes_factory.ns.SendData(sentData = [EnaClsAsset], senderApp = [lnAsset])
            #    instance_model.add_association(enaCls_ln_assoc)
            #    data_subnet_assoc = lang_classes_factory.ns.DataInTransit(transitData = [EnaOpnAsset], transitNetwork = [subNetAsset])
            #    instance_model.add_association(data_subnet_assoc)
            #    enaOpn_subnet_assoc = lang_classes_factory.ns.DataInTransit(transitData = [EnaClsAsset], transitNetwork = [subNetAsset])
            #    instance_model.add_association(enaOpn_subnet_assoc)   
            #if ((LNfindAll.attrib['lnClass']+"_"+LDeviceIter.attrib['inst']+"_"+LNfindAll.attrib['inst'] == "PTOC_OC4_1_1")):
            #    opAsset = lang_classes_factory.ns.IcsControlData(name = "Op")
            #    instance_model.add_asset(opAsset)
            #    op_ln_assoc = lang_classes_factory.ns.ReceiveData(receivedData = [opAsset], receiverApp = [lnAsset])
            #    instance_model.add_association(op_ln_assoc)
                #add connection to subnet
            #    op_subnet_assoc = lang_classes_factory.ns.DataInTransit(transitData = [opAsset], transitNetwork = [subNetAsset])
            #    instance_model.add_association(op_subnet_assoc)
            ln_ld_assoc = lang_classes_factory.ns.AppExecution(
            hostApp = [ldAsset], appExecutedApps = [lnAsset])
            instance_model.add_association(ln_ld_assoc)
#--------------------------------------------------------------
#Add the attacker to the model
attacker = AttackerAttachment()
instance_model.add_attacker(attacker)
#Give an entry point
attacker.entry_points = [(subNetAsset, ['accessUninspected'])]
attacker.add_entry_point(subNetAsset, 'accessUninspected')
instance_model.save_to_file('threat_model.yml')

attack_graph = AttackGraph(lang_graph, instance_model)
attack_graph.save_to_file('ag.yml')
apriori.calculate_viability_and_necessity(attack_graph)
attack_graph.save_to_file('post_ag.yml')
attack_graph.attach_attackers()

attacker = attack_graph.attackers[0]

#Choose below which asset is compromised
#attacker.compromise(attack_graph.get_node_by_id(61481))

#Add the generated model to the Neo4j server
#if maltoolbox.neo4j_configs['uri'] != "":
#    neo4j.ingest_model(instance_model,
#    maltoolbox.neo4j_configs['uri'],
#    maltoolbox.neo4j_configs['username'],
#    maltoolbox.neo4j_configs['password'],
#    maltoolbox.neo4j_configs['dbname'],
#    delete=True)
