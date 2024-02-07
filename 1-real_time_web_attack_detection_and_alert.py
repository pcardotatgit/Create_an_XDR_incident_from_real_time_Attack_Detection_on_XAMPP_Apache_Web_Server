'''
    for windows OS only
    Monitor log file of a web server 
    Copy every new stored logs lines and search into it in real time Web attacks based on patern matching and strings   
    located into the check_ids_signature() function.
    An alert is sent in real time to webex, everytime an attack is detected
    
    notice pip install pywin32 doesn't work we must use : python -m pip install pywin32
'''

import os
import sys
import win32file
import win32con
from create_XDR_incident import go_for_incident
from crayons import *

#path_to_watch = "." # look at the current directory
path_to_watch = "C:\\patrick\\zazou_dev_FY_23\\zazou_xdr_demos\\_logs.zmwsc"
file_to_watch = "access_log" # look for changes to a file called test.txt*

observables={}

targets=[
  {
    "type": "endpoint",
    "observables": [
      {
        "value": "Public Web Server",
        "type": "hostname"
      },
      {
        "value": "84.85.86.87",
        "type": "ip"
      },
      {
        "value": "00:E1:6D:26:24:E9",
        "type": "mac_address"
      }
    ],
    "observed_time": {
      "start_time": "2023-09-09T13:31:02.000Z",
      "end_time": "2023-09-09T13:31:02.000Z"
    }
  }
]

def check_ids_signature(line):
    indicator=""
    line=line.lower()
    title="Web Attack from "
    if '/phpmyadmin' in line and 'pma_password=' in line:
        indicator="Impact HIGH *;* phpmyadmin access attempt *;* "
        title="phpmyadmin access attempt from "
    elif "+or+" in line or "+like+" in line or "--+" in line or "+union+" in line or "drop+" in line or "+select+" in line:
        indicator="Impact High *;* SQLi Attack Attempt *;* " 
        title="SQLi Attack from "
    elif "script" in line or "alert" in line:
        indicator="Impact High *;* XSS Attack Attempt *;* " 
        title="XSS Attack from "
    elif "../" in line or "..%2F" in line or "..%5C" in line:
        indicator="Impact High *;* Directory Traversal Attack Attempt *;* " 
        title="Directory Traversal Attack from "
    elif "/cgi-bin/ViewLog.asp" in line or "Akitaskid.arm7" in line:
        indicator="Impact High *;* Device Vulnerability Exploit ( zyxel ) *;* "  
        title="Device Vulnerability Exploit ( zyxel ) from "
    elif "HelloThinkPHP" in line:
        indicator="Impact High *;* Application Vulnerability Exploit ( Wordpress ) *;* " 
        title="Application Vulnerability Exploit ( Wordpress ) from "
    elif "goform/setUsbUnload" in line:
        indicator="Impact High *;* Device Vulnerability Exploit ( Tenda AC1900 Router AC15 Model Remote Code Execution Vulnerability ) *;* "        
        title="Device Vulnerability Exploit ( Tenda AC1900 Router AC15 Model Remote Code Execution Vulnerability ) from "
    elif "netgear" in line:
        indicator="Impact High *;* Device Vulnerability Exploit ( Netgear ) *;* "
        title="Device Vulnerability Exploit ( Netgear ) from "        
    elif "/shell" in line and "wget" in line:
        indicator="Impact High *;* Device Vulnerability Exploit ( ---- ) *;* "
        title="Device Vulnerability Exploit ( shell execution ) from " 
    elif "HelloThink" in line:
        indicator="Impact High *;* Application Vulnerability Exploit ( HelloThink ) *;* " 
        title="Application Vulnerability Exploit ( HelloThink ) from " 
    elif "XDEBUG_SESSION_START=phpstorm" in line:
        indicator="Impact High *;* Application Vulnerability Exploit ( phpstorm ) *;* "
        title="Application Vulnerability Exploit ( phpstorm ) from "
    elif ( line.count('..')>2 ):
        indicator="Impact High *;* Directory Traversal *;* " 
        title="Directory Traversal attempt from "
    elif ( line.count('%')>10 ):
        indicator="Impact Medium *;* Obfuscation attempt *;* " 
        title="Patern Obfuscation attempt attempt from "
    elif "/etc/passwd" in line:
        indicator="Impact Medium *;* /etc/passwd access attempt *;* " 
        title="/etc/passwd access attempt from "
    elif '" 404 ' in line or '" 403 ' in line:
        #indicator="Impact Low *;* Web Site Resource Scan to non existing content *;* "   
        indicator=""
        title="scan for web application from "
    elif "/robots.txt" in line or "/sitemap.xml" in line:
        indicator="Impact Low *;* Web Site Mapping attempt robot.txt access*;* "  
        title="Web Site Mapping attempt robot.txt access from "
    else:
        indicator=""
    return (indicator,title)
 
def keep_this_ip_in_observables(line):
    ip=line.split(" ")[0]    
    if ip not in observables.keys(): 
        observables[ip]={'nb':1}
    else:
        observables[ip]['nb']+=1

def get_targets():
    # this function is supposed to parse the log or any other source in order to extract targets and put them into the returned list
    # in our case as we know the target, this is the Honeypot Web Server then we set statically the target value
    target_list=[]
    target_list.append('84.85.86.87')
    return target_list
    
def create_json_observables(ip_list,ip_target): 
    observables=[]
    relationships=[]
    observable_item={'type':'ip','value':ip_target[0]}
    observables.append(observable_item)     
    for item in ip_list:   
        observable_item={'type':'ip','value':item}
        observables.append(observable_item)
        relationship_item={
          "origin": "XDR Demo Detection",
          "origin_uri": "https://localhost:4000/",
          "relation": "Connected_To",
          "source": {
            "value":ip_target[0], # in our demo we only have one target
            "type":"ip"
          },
          "related": {
            "value":item,
            "type":"ip" 
          }
        }
        relationships.append(relationship_item)
    print('observables : ',green(observables,bold=True))  
    print('relationships : ',green(relationships,bold=True))
    return observables,relationships
        
def watch_log():
    file_out = open("./logs/out.txt","w")
    # Set up the bits we'll need for output
    ACTIONS = {
      1 : "Created",
      2 : "Deleted",
      3 : "Updated",
      4 : "Renamed from something",
      5 : "Renamed to something"
    }

    FILE_LIST_DIRECTORY = 0x0001
    hDir = win32file.CreateFile (
      path_to_watch,
      FILE_LIST_DIRECTORY,
      win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
      None,
      win32con.OPEN_EXISTING,
      win32con.FILE_FLAG_BACKUP_SEMANTICS,
      None
    )

    # Open the file we're interested in
    full_filename = path_to_watch+'\\'+file_to_watch
    a = open(full_filename, "r")

    # Throw away any exising log data
    a.read()

    # Wait for new data and call ProcessNewData for each new chunk that's written
    try:
        GO=1
        while GO:
          # Wait for a change to occur
          results = win32file.ReadDirectoryChangesW (
            hDir,
            1024,
            False,
            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
            None,
            None
          )
          
          # For each change, check to see if it's updating the file we're interested in
          for action, file in results:
            full_filename = os.path.join (path_to_watch, file)
            print (file, ACTIONS.get (action, "Unknown"))
            if file == file_to_watch:
                newText = a.read()
                if newText != "":
                    print('...Alert_check...')
                    title=""
                    alert,title=check_ids_signature(newText)
                    if alert!="":
                        ip_list=[]
                        print(newText)
                        line_out=alert+' *;* '+newText+'\n'
                        file_out.write(line_out)
                        keep_this_ip_in_observables(newText)
                        for item in observables:
                            print(cyan(observables[item]['nb']))
                            if observables[item]['nb']==1:
                                print(cyan(f"Observable to add to XDR Sighting : {item}",bold=True))
                                ip_list.append(item)      
                                target_list=get_targets()
                                observables_objects,observable_relationships=create_json_observables(ip_list,target_list)
                                print()
                                print(yellow('Create XDR Incident Now',bold=True))
                                print()
                                go_for_incident(observables_objects,targets,observable_relationships,title) 
                    if "/stopwatching" in newText:
                        print()
                        print('STOP WATCHING LOG FILE')
                        GO=0
        sys.exit()  
        file_out.close()

    except KeyboardInterrupt:
        print('interrupted!')
        sys.exit()
    
if __name__=="__main__":
    print()
    print('Path_to_watch : ',path_to_watch)
    print('file_to_watch : ',file_to_watch)
    print()
    print('START WATCHING LOGS')
    print()
    watch_log()