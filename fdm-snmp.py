import getpass
import json
import sys
import requests
import warnings

# Script Metadata
__author__ = "Anupam Pavithran (anpavith@cisco.com)"
__version__ = "1.2.0"

#After selecting a primary interface, it checks for subinterfaces and allows the user to choose one if available.
#If no subinterface is chosen, it defaults to the primary interface.

# Disable warnings for unverified HTTPS requests (not recommended for production)
requests.packages.urllib3.disable_warnings()

def auth():
	
	url = "https://"+device+"/api/fdm/latest/fdm/token"

	payload = ('{ "grant_type": "password","username": "%s", "password": "%s" }'%(username,password))	
	
	headers = {
			  	'Content-Type': 'application/json',
	  			'Accept': 'application/json'
			}
	
	r=None
	try:
	  r = requests.post(url, headers=headers, data = payload, verify=False)
	  print('Auth-Status code is ',r.status_code)
	  auth_body=json.loads(r.text)
	  #print(auth_body)
	  if r.status_code==500:
	  	print('Internal Server Error')
	  	sys.exit()

	  auth_token = auth_body.get('access_token')
	  if auth_token == None:
	      print("auth_token not found. Exiting...")
	      #print(auth_body)
	      sys.exit()
	  elif r.status_code==200:
	  	print('Successfully Authenticated')
	  	return(auth_token)
	except Exception as err:
	  print ("Error generated from auth() function --> "+str(err))
	  sys.exit()

def refresh():
	url = "https://"+device+"/api/fdm/latest/fdm/token"

	payload=('{"grant_type":"refresh_token","refresh_token":"%s"}'%(token))

	headers = {
			  	'Content-Type': 'application/json',
	  			'Accept': 'application/json'
			}
	
	r=None
	try:
	  r = requests.post(url, headers=headers, data = payload, verify=False)
	  auth_body=json.loads(r.text)
	  refresh_token = auth_body.get('refresh_token')
	  if refresh_token == None:
	      print("refresh token not found. Exiting...")
	      print(auth_body)
	      sys.exit()
	  else:
	  	return(refresh_token)
	except Exception as err:
	  print ("Error generated from auth() function --> "+str(err))
	  sys.exit()

def create_hostobj(name,ip):
	url = "https://"+device+"/api/fdm/latest/object/networks"

	payload={ "name": name, 
			  "description": "SNMP Server Host", 
			  "subType": "HOST", 
			  "value": ip, 
			  "dnsResolution": "IPV4_ONLY", 
			  "type": "networkobject"}

	headers = { 'Authorization': 'Bearer '+token,
			  	'Content-Type': 'application/json',
	  			'Accept': 'application/json'
			}

	r=None
	try:
	  r = requests.post(url, headers=headers, data = json.dumps(payload), verify=False)
	  #print('\nHTTP RESPONSE CODE', r.status_code)
	  response_body=json.loads(r.text)
	  
	  if r.status_code==200:
		  return response_body

	  else:
	  	  print(response_body)
	  	  sys.exit()


	except Exception as err:
	  print ("Error creating Host --> "+str(err))
	  sys.exit()

def create_snmpv3user(snmpv3_payload):

	url = "https://"+device+"/api/fdm/latest/object/snmpusers"


	headers = { 'Authorization': 'Bearer '+token,
			  	'Content-Type': 'application/json',
	  			'Accept': 'application/json'
			}

	r=None

	try:
	  r = requests.post(url, headers=headers, data = json.dumps(snmpv3_payload), verify=False)
	  #print('\nHTTP RESPONSE CODE', r.status_code)
	  response_body=json.loads(r.text)
	  
	  if r.status_code==200:
		  return response_body

	  else:
	  	  print(response_body)


	except Exception as err:
	  print ("Error creating Host --> "+str(err))
	  sys.exit()

def select_interface():

    url = "https://"+device+"/api/fdm/latest/devices/default/interfaces?limit=25"
    url_vlan = "https://"+device+"/api/fdm/latest/devices/default/vlaninterfaces?limit=25"
    url_po = "https://"+device+"/api/fdm/latest/devices/default/etherchannelinterfaces"
    url_sub = "https://"+device+"/api/fdm/latest/devices/default/interfaces/{parentId}/subinterfaces"  # Added URL for subinterfaces

    headers = { 'Authorization': 'Bearer '+token,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
              }

    r = None

    try:
        # Main interfaces, VLAN, and Port-Channels
        r = requests.get(url, headers=headers, verify=False)
        r_vlan = requests.get(url_vlan, headers=headers, verify=False)
        r_po = requests.get(url_po, headers=headers, verify=False)

        responses = [r]
        if r_vlan.status_code == 200:
            responses.append(r_vlan)
        if r_po.status_code == 200:
            responses.append(r_po)

        # Fetch subinterfaces (assuming a parent interface is selected)
        valid_interface = []
        interface_counter = 0
        if r.status_code == 200:
            for response in responses:
                for interface in response.json()['items']:
                    if interface['name'] is not None and interface['name'] != '':
                        valid_interface.append(interface)
                        print(interface_counter + 1, valid_interface[interface_counter]['name'], valid_interface[interface_counter]['hardwareName'])
                        interface_counter += 1

            interface_selection = int(input("Select the Phyinterface (Integer value only) : ")) - 1
            selected_interface = valid_interface[interface_selection]

            # If the selected interface has subinterfaces
            sub_url = url_sub.replace("{parentId}", selected_interface['id'])
            r_sub = requests.get(sub_url, headers=headers, verify=False)
            if r_sub.status_code == 200:
                subinterfaces = r_sub.json().get('items', [])
                if subinterfaces:
                    print("Subinterfaces found for", selected_interface['name'])
                    for idx, sub in enumerate(subinterfaces):
                        print(idx + 1, sub['name'], sub['id'])
                    sub_selection = int(input("Select the subinterface (or press Enter to skip): ")) - 1
                    return subinterfaces[sub_selection] if sub_selection >= 0 else selected_interface
            return selected_interface
        else:
            print(responses)

    except Exception as err:
        print("Error in interface selection --> " + str(err))
        sys.exit()

def create_snmphost(sec_Configuration,snmp_hostname):

	url = "https://"+device+"/api/fdm/latest/object/snmphosts"

	payload={

				"name": snmp_hostname,
				"managerAddress": {
									"version": host['version'],
									"name": host['name'],
									"id": host['id'],
									"type": host['type']
								  },

				"pollEnabled": True,
				"trapEnabled": True,

				"securityConfiguration": sec_Configuration,

				"interface": {
								"version": interface['version'],
								"name": interface['name'],
								"id": interface['id'],
								"type": interface['type']
								},

				"type": "snmphost"

				}

	headers = { 'Authorization': 'Bearer '+token,
			  	'Content-Type': 'application/json',
	  			'Accept': 'application/json'
			}

	r=None

	try:
	  r = requests.post(url, headers=headers, data = json.dumps(payload), verify=False)
	  #print('\nHTTP RESPONSE CODE', r.status_code)
	  response_body=json.loads(r.text)
	  
	  if r.status_code==200:
		  print('Successfully Created, please deploy and check SNMP config')
		  #print(response_body)

	  else:
	  	  print(response_body)


	except Exception as err:
	  print ("Error creating Host --> "+str(err))
	  sys.exit()

''' MAIN STARTS HERE '''

print('###########################################################')
print('#                   CONFIGURE SNMP ON FDM                 #')
print('###########################################################')


device = input("Enter the device IP address: ")
username = input("Enter the username of the FTD: ")
password = getpass.getpass("Enter the password of the FTD: ")


token=auth()

ver_flag=int(input('Would you like to configure (1) SNMPv2 or  (2) SNMPv3 : ' ))

name=input("Enter the SNMP Server object name : ")
ip= input("Enter the SNMP Server object IP : ")

host=create_hostobj(name, ip) #version, name, id and type

sec_Configuration={}

if ver_flag==1:

	community_str=input('Enter SNMPv2 community string : ')
	sec_Configuration= {
    					"community": community_str,
    					"type": "snmpv2csecurityconfiguration"
						}

elif ver_flag==2:
	snmpv3_payload={}
	snmpv3_payload['type']='snmpuser'
	snmpv3_payload['name'] = input('Enter SNMPv3 username : ')
	snmpv3_payload['securityLevel'] = input("Enter Security Level => Options ['AUTH', 'NOAUTH', 'PRIV'] :  ")

	if snmpv3_payload['securityLevel'] in ['AUTH','PRIV']:
		snmpv3_payload['authenticationAlgorithm'] = input("Enter authentication Algorithm => Options ['SHA', 'SHA256'] : ")
		snmpv3_payload['authenticationPassword']=input("Enter authentication password : ")

	if snmpv3_payload['securityLevel'] == "PRIV":
		snmpv3_payload['encryptionAlgorithm']= input("Enter encryption Algorithm => Options ['AES128', 'AES192', 'AES256', '3DES'] : ")
		snmpv3_payload['encryptionPassword']=input("Enter encryption password : ")
	user=create_snmpv3user(snmpv3_payload) #version, name, id and type

	sec_Configuration = {
								"authentication": {
													"version": user['version'],
													"name": user['name'],
													"id": user['id'],
													"type": user['type']
													},
								"type": "snmpv3securityconfiguration"
							}

print('###########################################################')

interface=select_interface() #version, name, id and type

snmp_hostname=input('Enter SNMP host object name : ')

print('###########################################################')
create_snmphost(sec_Configuration,snmp_hostname)
print('###########################################################')
