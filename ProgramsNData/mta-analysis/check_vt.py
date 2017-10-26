import os
import requests
import time
import sys

API_KEY = 'dda4c35828204f0246c88e943a63f79bb7b472c220d5c512281a6ded2ea3f121'

zip_dir = 'files'
extracted_dir = 'files\extracted'
extension = ".zip"




def check_vt(file_path):
    file_name = os.path.basename(file_path)
    print ("    file: ", file_name)
    resource = get_resource(file_path)
    params = {'apikey': API_KEY, 'resource': resource}
    headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  My Python requests library example client or username"
     }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
    params=params, headers=headers)
    json_response = response.json()
    try:
        print ("    result: ", json_response['positives'] , "/" ,  json_response["total"])
    except Exception:
        pass
    scans = json_response['scans']
    return check_cve(scans)


def check_cve(scans):
    cve_list = []
    for key, value in scans.items():
        result = value['result']
        if result is not None:
            cve = get_cve(result)
            if cve is not None:
                if not cve_list:
                    cve_list.append(cve) 
                else:
                    if cve not in cve_list:
                        print ("    conflicting cve detected")
                        cve_list.append(cve)
    if cve_list:
        output = "/".join(cve_list)
    else :
        output = None
    return output

def get_cve(string):
    string = string.upper()
    for i in range(0, len(string) - 2):
        if string[i] == 'C' and string[i+1] == 'V' and string[i+2] == 'E':
            if string[i+3] == '-' or string[i+3] == '_':
                return string[i:i+3] + '-' + string[i+4:i+8] + '-' + string[i+9:i+13]
            elif string[i+3].isdigit():
                length = len(string)
                num_len = len (string[i+3 : length])
                if num_len == 6:
                    return string[i:i+3] + '-20' + string[i+3:i+5] + '-' + string[i+5:i+9]
                elif num_len == 8:
                    return string[i:i+3] + '-' + string[i+3:i+7] + '-' + string[i+7:i+11]
    return None

def get_resource(file_path):
    params = {'apikey': API_KEY }
    file_name = os.path.basename(file_path)
    files = {'file': (file_name, open(file_path, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    resource = json_response['resource']
    return resource

def check_zip():
    for item in os.listdir(zip_dir):
        if item.endswith(extension):
            item_path = os.path.join("files", item)
            check_vt(item_path)
            time.sleep(60)

def check_swf():
    for item in os.listdir(extracted_dir):
        new_dir = os.path.join(extracted_dir, item)
        print ("Folder :", new_dir)
        print ()
        cve_list = []
        for file in os.listdir(new_dir):
            if file.endswith(".swf"):
                item_path = os.path.join(new_dir, file)
                cve = check_vt(item_path)
                cve_list.append(cve)
                print ()
                time.sleep(60)
        print ("    ", cve_list)
        print ()
        print ("     --- --- --- --- --- ")
        print ()

#check_zip()
sys.stdout = open("vt_result.txt","w")
check_swf()

sys.stdout.close()