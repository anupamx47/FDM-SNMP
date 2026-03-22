import getpass
import json
import sys
import requests

# Script Metadata
__author__ = "Anupam Pavithran (anpavith@cisco.com)"
__version__ = "2.0.0"

# After selecting a primary interface, it checks for subinterfaces and allows the user to choose one if available.
# If no subinterface is chosen, it defaults to the primary interface.

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
      if r.status_code==500:
        print('Internal Server Error')
        sys.exit()
      auth_token = auth_body.get('access_token')
      if auth_token == None:
          print("auth_token not found. Exiting...")
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


def api_headers():
    return {
        'Authorization': 'Bearer '+token,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


# ==================== Network Host Object ====================

def create_hostobj(name,ip):
    url = "https://"+device+"/api/fdm/latest/object/networks"
    payload={ "name": name,
              "description": "SNMP Server Host",
              "subType": "HOST",
              "value": ip,
              "dnsResolution": "IPV4_ONLY",
              "type": "networkobject"}
    try:
      r = requests.post(url, headers=api_headers(), data = json.dumps(payload), verify=False)
      response_body=json.loads(r.text)
      if r.status_code==200:
          return response_body
      else:
          print(response_body)
          sys.exit()
    except Exception as err:
      print ("Error creating Host --> "+str(err))
      sys.exit()


# ==================== SNMPv3 User CRUD ====================

def create_snmpv3user(snmpv3_payload):
    url = "https://"+device+"/api/fdm/latest/object/snmpusers"
    try:
      r = requests.post(url, headers=api_headers(), data = json.dumps(snmpv3_payload), verify=False)
      response_body=json.loads(r.text)
      if r.status_code==200:
          return response_body
      else:
          print(response_body)
    except Exception as err:
      print ("Error creating SNMPv3 User --> "+str(err))
      sys.exit()


def list_snmpv3users():
    url = "https://"+device+"/api/fdm/latest/object/snmpusers"
    try:
      r = requests.get(url, headers=api_headers(), verify=False)
      if r.status_code==200:
          items = r.json().get('items', [])
          if not items:
              print('\nNo SNMPv3 users found.')
              return []
          print('\n{:<5} {:<25} {:<40} {:<15}'.format('#', 'Name', 'ID', 'Security Level'))
          print('-' * 85)
          for idx, user in enumerate(items):
              print('{:<5} {:<25} {:<40} {:<15}'.format(
                  idx + 1,
                  user.get('name', 'N/A'),
                  user.get('id', 'N/A'),
                  user.get('securityLevel', 'N/A')
              ))
          return items
      else:
          print(r.json())
          return []
    except Exception as err:
      print ("Error listing SNMPv3 users --> "+str(err))
      return []


def get_snmpv3user(user_id):
    url = "https://"+device+"/api/fdm/latest/object/snmpusers/"+user_id
    try:
      r = requests.get(url, headers=api_headers(), verify=False)
      if r.status_code==200:
          return r.json()
      else:
          print(r.json())
          return None
    except Exception as err:
      print ("Error getting SNMPv3 user --> "+str(err))
      return None


def update_snmpv3user(user_id, payload):
    url = "https://"+device+"/api/fdm/latest/object/snmpusers/"+user_id
    try:
      r = requests.put(url, headers=api_headers(), data=json.dumps(payload), verify=False)
      if r.status_code==200:
          print('SNMPv3 user updated successfully.')
          return r.json()
      else:
          print(r.json())
          return None
    except Exception as err:
      print ("Error updating SNMPv3 user --> "+str(err))
      return None


def delete_snmpv3user(user_id):
    url = "https://"+device+"/api/fdm/latest/object/snmpusers/"+user_id
    try:
      r = requests.delete(url, headers=api_headers(), verify=False)
      if r.status_code in [200, 204]:
          print('SNMPv3 user deleted successfully.')
          return True
      else:
          print(r.json())
          return False
    except Exception as err:
      print ("Error deleting SNMPv3 user --> "+str(err))
      return False


# ==================== Interface Selection ====================

def select_interface():
    url = "https://"+device+"/api/fdm/latest/devices/default/interfaces?limit=25"
    url_vlan = "https://"+device+"/api/fdm/latest/devices/default/vlaninterfaces?limit=25"
    url_po = "https://"+device+"/api/fdm/latest/devices/default/etherchannelinterfaces"
    url_sub = "https://"+device+"/api/fdm/latest/devices/default/interfaces/{parentId}/subinterfaces"

    try:
        r = requests.get(url, headers=api_headers(), verify=False)
        r_vlan = requests.get(url_vlan, headers=api_headers(), verify=False)
        r_po = requests.get(url_po, headers=api_headers(), verify=False)

        responses = [r]
        if r_vlan.status_code == 200:
            responses.append(r_vlan)
        if r_po.status_code == 200:
            responses.append(r_po)

        valid_interface = []
        interface_counter = 0
        if r.status_code == 200:
            for response in responses:
                for interface in response.json()['items']:
                    if interface['name'] is not None and interface['name'] != '':
                        valid_interface.append(interface)
                        print(interface_counter + 1, valid_interface[interface_counter]['name'], valid_interface[interface_counter]['hardwareName'])
                        interface_counter += 1

            interface_selection = int(input("Select the interface (Integer value only) : ")) - 1
            selected_interface = valid_interface[interface_selection]

            sub_url = url_sub.replace("{parentId}", selected_interface['id'])
            r_sub = requests.get(sub_url, headers=api_headers(), verify=False)
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


# ==================== SNMP Host CRUD ====================

def create_snmphost(sec_Configuration, snmp_hostname, host_obj, iface):
    url = "https://"+device+"/api/fdm/latest/object/snmphosts"
    payload={
        "name": snmp_hostname,
        "managerAddress": {
            "version": host_obj['version'],
            "name": host_obj['name'],
            "id": host_obj['id'],
            "type": host_obj['type']
        },
        "pollEnabled": True,
        "trapEnabled": True,
        "securityConfiguration": sec_Configuration,
        "interface": {
            "version": iface['version'],
            "name": iface['name'],
            "id": iface['id'],
            "type": iface['type']
        },
        "type": "snmphost"
    }
    try:
      r = requests.post(url, headers=api_headers(), data = json.dumps(payload), verify=False)
      response_body=json.loads(r.text)
      if r.status_code==200:
          print('Successfully Created, please deploy and check SNMP config')
      else:
          print(response_body)
    except Exception as err:
      print ("Error creating SNMP Host --> "+str(err))
      sys.exit()


def list_snmphosts():
    url = "https://"+device+"/api/fdm/latest/object/snmphosts"
    try:
      r = requests.get(url, headers=api_headers(), verify=False)
      if r.status_code==200:
          items = r.json().get('items', [])
          if not items:
              print('\nNo SNMP hosts found.')
              return []
          print('\n{:<5} {:<25} {:<40} {:<15} {:<10} {:<10}'.format(
              '#', 'Name', 'ID', 'Interface', 'Poll', 'Trap'))
          print('-' * 105)
          for idx, snmphost in enumerate(items):
              iface = snmphost.get('interface', {})
              print('{:<5} {:<25} {:<40} {:<15} {:<10} {:<10}'.format(
                  idx + 1,
                  snmphost.get('name', 'N/A'),
                  snmphost.get('id', 'N/A'),
                  iface.get('name', 'N/A'),
                  str(snmphost.get('pollEnabled', 'N/A')),
                  str(snmphost.get('trapEnabled', 'N/A'))
              ))
          return items
      else:
          print(r.json())
          return []
    except Exception as err:
      print ("Error listing SNMP hosts --> "+str(err))
      return []


def get_snmphost(host_id):
    url = "https://"+device+"/api/fdm/latest/object/snmphosts/"+host_id
    try:
      r = requests.get(url, headers=api_headers(), verify=False)
      if r.status_code==200:
          return r.json()
      else:
          print(r.json())
          return None
    except Exception as err:
      print ("Error getting SNMP host --> "+str(err))
      return None


def update_snmphost(host_id, payload):
    url = "https://"+device+"/api/fdm/latest/object/snmphosts/"+host_id
    try:
      r = requests.put(url, headers=api_headers(), data=json.dumps(payload), verify=False)
      if r.status_code==200:
          print('SNMP host updated successfully. Please deploy to apply changes.')
          return r.json()
      else:
          print(r.json())
          return None
    except Exception as err:
      print ("Error updating SNMP host --> "+str(err))
      return None


def delete_snmphost(host_id):
    url = "https://"+device+"/api/fdm/latest/object/snmphosts/"+host_id
    try:
      r = requests.delete(url, headers=api_headers(), verify=False)
      if r.status_code in [200, 204]:
          print('SNMP host deleted successfully. Please deploy to apply changes.')
          return True
      else:
          print(r.json())
          return False
    except Exception as err:
      print ("Error deleting SNMP host --> "+str(err))
      return False


# ==================== SNMP Server Settings ====================

def get_snmp_server():
    url = "https://"+device+"/api/fdm/latest/devicesettings/default/snmpservers"
    try:
      r = requests.get(url, headers=api_headers(), verify=False)
      if r.status_code==200:
          items = r.json().get('items', [])
          if items:
              return items[0]
          print('No SNMP server settings found.')
          return None
      else:
          print(r.json())
          return None
    except Exception as err:
      print ("Error getting SNMP server settings --> "+str(err))
      return None


def update_snmp_server(server_id, payload):
    url = "https://"+device+"/api/fdm/latest/devicesettings/default/snmpservers/"+server_id
    try:
      r = requests.put(url, headers=api_headers(), data=json.dumps(payload), verify=False)
      if r.status_code==200:
          print('SNMP server settings updated successfully. Please deploy to apply changes.')
          return r.json()
      else:
          print(r.json())
          return None
    except Exception as err:
      print ("Error updating SNMP server settings --> "+str(err))
      return None


# ==================== Workflow Functions ====================

def build_security_config():
    ver_flag=int(input('Configure (1) SNMPv2 or (2) SNMPv3 : '))
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
        snmpv3_payload['securityLevel'] = input("Enter Security Level => Options ['AUTH', 'NOAUTH', 'PRIV'] : ")

        if snmpv3_payload['securityLevel'] in ['AUTH','PRIV']:
            snmpv3_payload['authenticationAlgorithm'] = input("Enter authentication Algorithm => Options ['SHA', 'SHA256'] : ")
            snmpv3_payload['authenticationPassword']=input("Enter authentication password : ")

        if snmpv3_payload['securityLevel'] == "PRIV":
            snmpv3_payload['encryptionAlgorithm']= input("Enter encryption Algorithm => Options ['AES128', 'AES192', 'AES256', '3DES'] : ")
            snmpv3_payload['encryptionPassword']=input("Enter encryption password : ")

        user=create_snmpv3user(snmpv3_payload)
        sec_Configuration = {
            "authentication": {
                "version": user['version'],
                "name": user['name'],
                "id": user['id'],
                "type": user['type']
            },
            "type": "snmpv3securityconfiguration"
        }
    else:
        print('Invalid selection.')
        return None

    return sec_Configuration


def do_create():
    print('\n--- Create SNMP Configuration ---')
    name=input("Enter the SNMP Server object name : ")
    ip= input("Enter the SNMP Server object IP : ")
    host_obj=create_hostobj(name, ip)

    sec_Configuration = build_security_config()
    if sec_Configuration is None:
        return

    print('\n--- Select Interface ---')
    iface=select_interface()
    snmp_hostname=input('Enter SNMP host object name : ')
    create_snmphost(sec_Configuration, snmp_hostname, host_obj, iface)


def do_read():
    print('\n--- View SNMP Configuration ---')
    print('1. List SNMP Hosts')
    print('2. List SNMPv3 Users')
    print('3. View SNMP Host Details')
    print('4. View SNMPv3 User Details')
    print('5. View SNMP Server Settings')
    print('6. Back')
    choice = input('Select an option : ')

    if choice == '1':
        list_snmphosts()
    elif choice == '2':
        list_snmpv3users()
    elif choice == '3':
        items = list_snmphosts()
        if items:
            selection = int(input('Select SNMP host to view details (Integer) : ')) - 1
            detail = get_snmphost(items[selection]['id'])
            if detail:
                print(json.dumps(detail, indent=2))
    elif choice == '4':
        items = list_snmpv3users()
        if items:
            selection = int(input('Select SNMPv3 user to view details (Integer) : ')) - 1
            detail = get_snmpv3user(items[selection]['id'])
            if detail:
                print(json.dumps(detail, indent=2))
    elif choice == '5':
        server = get_snmp_server()
        if server:
            print(json.dumps(server, indent=2))
    elif choice == '6':
        return


def do_update():
    print('\n--- Update SNMP Configuration ---')
    print('1. Update SNMP Host')
    print('2. Update SNMPv3 User')
    print('3. Update SNMP Server Settings')
    print('4. Back')
    choice = input('Select an option : ')

    if choice == '1':
        items = list_snmphosts()
        if not items:
            return
        selection = int(input('Select SNMP host to update (Integer) : ')) - 1
        existing = get_snmphost(items[selection]['id'])
        if not existing:
            return

        print('\nCurrent configuration:')
        print(json.dumps(existing, indent=2))
        print('\nWhat would you like to update?')
        print('1. Toggle Poll Enabled (currently: %s)' % existing.get('pollEnabled'))
        print('2. Toggle Trap Enabled (currently: %s)' % existing.get('trapEnabled'))
        print('3. Change Interface')
        print('4. Cancel')
        update_choice = input('Select an option : ')

        if update_choice == '1':
            existing['pollEnabled'] = not existing['pollEnabled']
            update_snmphost(existing['id'], existing)
        elif update_choice == '2':
            existing['trapEnabled'] = not existing['trapEnabled']
            update_snmphost(existing['id'], existing)
        elif update_choice == '3':
            new_iface = select_interface()
            existing['interface'] = {
                "version": new_iface['version'],
                "name": new_iface['name'],
                "id": new_iface['id'],
                "type": new_iface['type']
            }
            update_snmphost(existing['id'], existing)
        elif update_choice == '4':
            return

    elif choice == '2':
        items = list_snmpv3users()
        if not items:
            return
        selection = int(input('Select SNMPv3 user to update (Integer) : ')) - 1
        existing = get_snmpv3user(items[selection]['id'])
        if not existing:
            return

        print('\nCurrent configuration:')
        print(json.dumps(existing, indent=2))
        print('\nWhat would you like to update?')
        print('1. Security Level')
        print('2. Authentication Algorithm & Password')
        print('3. Encryption Algorithm & Password')
        print('4. Cancel')
        update_choice = input('Select an option : ')

        if update_choice == '1':
            existing['securityLevel'] = input("Enter new Security Level => Options ['AUTH', 'NOAUTH', 'PRIV'] : ")
            if existing['securityLevel'] in ['AUTH', 'PRIV']:
                existing['authenticationAlgorithm'] = input("Enter authentication Algorithm => Options ['SHA', 'SHA256'] : ")
                existing['authenticationPassword'] = input("Enter authentication password : ")
            if existing['securityLevel'] == 'PRIV':
                existing['encryptionAlgorithm'] = input("Enter encryption Algorithm => Options ['AES128', 'AES192', 'AES256', '3DES'] : ")
                existing['encryptionPassword'] = input("Enter encryption password : ")
            update_snmpv3user(existing['id'], existing)
        elif update_choice == '2':
            existing['authenticationAlgorithm'] = input("Enter authentication Algorithm => Options ['SHA', 'SHA256'] : ")
            existing['authenticationPassword'] = input("Enter authentication password : ")
            update_snmpv3user(existing['id'], existing)
        elif update_choice == '3':
            existing['encryptionAlgorithm'] = input("Enter encryption Algorithm => Options ['AES128', 'AES192', 'AES256', '3DES'] : ")
            existing['encryptionPassword'] = input("Enter encryption password : ")
            update_snmpv3user(existing['id'], existing)
        elif update_choice == '4':
            return

    elif choice == '3':
        server = get_snmp_server()
        if not server:
            return
        print('\nCurrent SNMP Server Settings:')
        print(json.dumps(server, indent=2))
        print('\nWhat would you like to update?')
        print('1. Contact')
        print('2. Location')
        print('3. Cancel')
        update_choice = input('Select an option : ')

        if update_choice == '1':
            server['contact'] = input('Enter new contact : ')
            update_snmp_server(server['id'], server)
        elif update_choice == '2':
            server['location'] = input('Enter new location : ')
            update_snmp_server(server['id'], server)
        elif update_choice == '3':
            return

    elif choice == '4':
        return


def do_delete():
    print('\n--- Delete SNMP Configuration ---')
    print('1. Delete SNMP Host')
    print('2. Delete SNMPv3 User')
    print('3. Back')
    choice = input('Select an option : ')

    if choice == '1':
        items = list_snmphosts()
        if not items:
            return
        selection = int(input('Select SNMP host to delete (Integer) : ')) - 1
        confirm = input('Are you sure you want to delete "%s"? (yes/no) : ' % items[selection].get('name'))
        if confirm.lower() == 'yes':
            delete_snmphost(items[selection]['id'])

    elif choice == '2':
        items = list_snmpv3users()
        if not items:
            return
        selection = int(input('Select SNMPv3 user to delete (Integer) : ')) - 1
        confirm = input('Are you sure you want to delete "%s"? (yes/no) : ' % items[selection].get('name'))
        if confirm.lower() == 'yes':
            delete_snmpv3user(items[selection]['id'])

    elif choice == '3':
        return


''' MAIN STARTS HERE '''

if __name__ == '__main__':
    print('###########################################################')
    print('#                   CONFIGURE SNMP ON FDM                 #')
    print('###########################################################')

    device = input("Enter the device IP address: ")
    username = input("Enter the username of the FTD: ")
    password = getpass.getpass("Enter the password of the FTD: ")

    token=auth()

    while True:
        print('\n###########################################################')
        print('#                      SNMP MENU                          #')
        print('###########################################################')
        print('1. Create SNMP Configuration')
        print('2. View SNMP Configuration')
        print('3. Update SNMP Configuration')
        print('4. Delete SNMP Configuration')
        print('5. Exit')
        print('###########################################################')

        choice = input('Select an option : ')

        if choice == '1':
            do_create()
        elif choice == '2':
            do_read()
        elif choice == '3':
            do_update()
        elif choice == '4':
            do_delete()
        elif choice == '5':
            print('Exiting...')
            sys.exit()
        else:
            print('Invalid option. Please try again.')
