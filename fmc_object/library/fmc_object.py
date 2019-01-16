#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}
DOCUMENTATION = r'''
---
module: fmc_objects
short_description: Add Objects to FMC
description:
- Add/remove host objects
- Add/remove network objects
- Add/remove object ranges.

options:
  domain:
    description:
    - Name of your domain.
    - Only works with Global domain and domains that use Global as the parent. Multiple Parent domains are not supported.
    default: Global
  objecttype:
    description:
    - Host, a single IP address
    - Network, CIDR address
    - Range, Range of IP address
    choices: [Host, Network, Range]
  objectname:
    description:
    - The name of the object. Maximum of 64 characters. Name should start with
    either alphabet or underscore and follower with either alphanumeric
    or special characters (-,_,+,.)
  hostip:
    description:
    - Used for a single IP address
    - Required if objecttype is Host
  networkip:
    description:
    - CIDR Address. Example: 192.168.1.0/24
    - Required if objecttype is Network
  rangeip:
    description:
    - Range of IPs with no spaces used. Example: 192.168.1.0-192.168.1.20
    - Required if objecttype is Range
  state:
    description:
    - If C(present), will verify objects are present and will create if needed.
    - If C(absent), will verify objects are present and will delete if needed.
    choices: [present, absent]
    default: present
  

requirements:
- urllib3
- requests
- json
- time
- sys
- re
authors:
- Derrick Johnson @derricktj
- Tyler Shannon @Red--
'''
EXAMPLES = r'''
- name: Create Host Object
  fmc_object:
    hostname: 1.1.1.1
    username: admin
    password: password
    objecttype: Host
    objectname: DemoHost1
    hostip: 192.168.1.1
    
- name: Remove Host Object
  fmc_object:
    hostname: 1.1.1.1
    username: admin
    password: password
    objecttype: Host
    objectname: DemoHost1
    hostip: 192.168.1.1
    state: absent

- name: Create Network Object
  fmc_object:
    hostname: 1.1.1.1
    username: admin
    password: password
    objecttype: Network
    objectname: DemoNetwork1
    networkip: 192.168.1.0/24

- name: Create Object Range
  fmc_object:
    hostname: 1.1.1.1
    username: admin
    password: password
    objecttype: Range
    objectname: DemoRange1
    rangeip: 192.168.1.0-192.168.1.255

- name: Using different domains
  fmc_object:
    hostname: 1.1.1.1
    username: admin
    password: password
    domain: FMC_Test_Domain
    objecttype: Range
    objectname: DemoRange1
    rangeip: 192.168.1.0-192.168.1.255
'''

from ansible.module_utils.basic import AnsibleModule

def main():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        hostname=dict(type='str', required=True),
        validate_certs=dict(type='str', choices=['yes', 'no'], default='yes'),
        domain=dict(type='str', default='Global'),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        objecttype=dict(type='str', required=True, choices=['Host', 'Network', 'Range']),
        objectname=dict(type='str', required=True),
        hostip=dict(type='str'),
        networkip=dict(type='str'),
        rangeip=dict(type='str')
    )
    
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False,
        required_if=[
            ['objecttype', 'Host', ['hostip']],
            ['objecttype', 'Network', ['networkip']],
            ['objecttype', 'Range', ['rangeip']]
        ]
    )

    err = False
    changed = False
    
    import urllib3
    import requests
    import json
    import time
    import sys
    import re

    #Disable Python Cert Warnings
    if module.params['validate_certs'] == "no":
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #User Inputs
    username = module.params['username']
    password = module.params['password']
    hostname = module.params['hostname']
    domain = module.params['domain']
    objecttype = module.params['objecttype']
    objectname = module.params['objectname']
    hostip = module.params['hostip']
    networkip = module.params['networkip']
    rangeip = module.params['rangeip']
    state = module.params['state']

    # Generate Token from Cisco FMC, pull tokens, and map token headers to a variable.
    login = requests.post('https://' + hostname + '/api/fmc_platform/v1/auth/generatetoken',auth=(username,password),verify=False)
    access_token = login.headers['x-auth-access-token']
    refresh_token = login.headers['x-auth-refresh-token']
    headers = {'Content-Type':'application/json','x-auth-access-token':access_token,'x-auth-refresh-token':refresh_token}

    DomainHeaders = login.headers['DOMAINS']
    #RegEx to clean up domain string
    DomainClean = re.sub('\[|\{|\]|\}|\"|\s|name|uuid|\:','', DomainHeaders )
    DomainList = DomainClean.split(',')

    #append Global/ to domain name
    #Module does not support subdomains that are not within Global.
    if domain != "Global":
        domain = "Global/"+domain

    if domain not in DomainList:
        err = True
        module.fail_json(msg="Invaild Domain Selection" + domain)

    i = DomainList.index(domain)
    DomainID = DomainList[i+1]
    del i #Cleanup

    #Increase search limit to 1000 (max)
    offset = '?offset=0&limit=1000'

    def pageNumberCheck(URL):
        #Page Number Getter: Make an API call and determine the number of pages needing to iterate through.
        try:
            r = requests.get(URL+offset,headers=headers,verify=False)
            status_code = r.status_code
            response = r.text

            if status_code == 200:
                if r : r.close()
                json_response = json.loads(response)
                pages = json_response['paging']['pages']
            else:
                err = True
                module.fail_json(msg="Error Code: " + str(status_code) + " Could not find the number of pages")

        except requests.exceptions.HTTPError as err:
            err = True
            module.fail_json(msg="Error Code: " + str(status_code) + "HTTP Error")
            pages = 0
        return pages

    def CheckIP(URLType, TypeIP):
        r = requests.get("https://" + hostname + "/api/fmc_config/v1/domain/" + DomainID + "/object/" + URLType + "/" + ObjectID,headers=headers,verify=False)
        status_code = r.status_code
        response = r.text
        json_response = json.loads(response)
        IP = json_response['value']
        if IP == TypeIP:
            if state == "present":
                changed = False
                #No change. This "if" really isn't needed but helps me keep things straight.
            if state == "absent":
                r = requests.delete("https://" + hostname + "/api/fmc_config/v1/domain/" + DomainID + "/object/" + URLType + "/" + ObjectID,headers=headers,verify=False)
                status_code = r.status_code
                if status_code == 200:
                    module.exit_json(changed=True)
                    #Object deleted
                if status_code != 200:
                    err = True
                    module.fail_json(msg="Error Code: " + str(status_code) + " Verify the object isn't in use.")
            
        if IP != TypeIP:
            err = True
            module.fail_json(msg="Object Name: " + objectname + " already in use with a different IP: " + IP)
        return IP

    URL = "https://" + hostname + "/api/fmc_config/v1/domain/" + DomainID + "/object/networkaddresses"
    #Finding the number of pages.
    pages = pageNumberCheck(URL)

    #Create lists first to add objects to them
    ObjectName_List=[]
    Type_List=[]
    ID_List=[]

    for i in range(pages):
        offset2 = '?offset=%d&limit=1000' % (i*1000)
        r = requests.get(URL+offset2,headers=headers,verify=False)
        status_code = r.status_code
        response = r.text
        if status_code == 200:
            #Successfully downloaded objects.
            if r : r.close()  # Close the connection.
            # Load the response as JSON, then set to variable items for list comprehension.
            json_response = json.loads(response)
            items = json_response['items']

            ObjectName_List.extend([i['name'] for i in items])
            Type_List.extend([i['type'] for i in items])
            ID_List.extend([i['id'] for i in items])

    del json_response #Cleanup
    del items #Cleanup
    

    #OBJECT NAME ALREADY TAKEN
    if objectname in ObjectName_List:
        i = ObjectName_List.index(objectname)
        ObjectType = Type_List[i]
        ObjectID = ID_List[i] #Used to build the URL to search the API for the object
        #del ObjectName_List #No longer needed at this point
        #del Type_List #No longer needed at this point
        #del ID_List #No longer needed at this point
        if ObjectType == "Host":
            IP = CheckIP(URLType="hosts", TypeIP=hostip)
                    
        if ObjectType == "Network":
            IP = CheckIP(URLType="networks", TypeIP=networkip)
                    
        if ObjectType == "Range":
            IP = CheckIP(URLType="ranges", TypeIP=rangeip)
    #OBJECT NAME NOT IN USE
    if objectname not in ObjectName_List and state == "present":
        #del ObjectName_List #No longer needed at this point.
        #del Type_List #No longer needed at this point
        #del ID_List #No longer needed at this point
        if objecttype == "Host":
            objtype = 'hosts'
            value = hostip
        if objecttype == "Range":
            objtype = 'ranges'
            value = rangeip
        if objecttype == 'Network':
            objtype = 'networks'
            value = networkip

        objectpost = {
            "name": objectname,
            "value": value,
            "type": objecttype,
        }

        URL = "https://" + hostname + "/api/fmc_config/v1/domain/" + DomainID + "/object/" + objtype

        r = requests.post(URL,json.dumps(objectpost),headers=headers,verify=False)
        status_code = r.status_code
        response = r.text

        if status_code == 429:
            while True:
                if status_code == 429:
                    #Too many API Requests. Waiting 3 seconds.
                    if r : r.close()
                    time.sleep(3)
                    r = requests.post(URL,json.dumps(objectpost),headers=headers,verify=False)
                    status_code = r.status_code
                    response = r.text
                else:
                    break

        if status_code == 201:
            module.exit_json(changed=True)
            #POST object successful.

        if status_code != 201:
            err = True
            module.fail_json(msg="Error Code: " + str(status_code) + " Could not apply new object named: " + objectname)
            #This should only happen if there is a connection problem as pervious checks made sure the object didn't exist
        if r : r.close()
        
    module.exit_json(changed=False)
                    
if __name__ == '__main__':
    main()
