import os
import requests
import time
import sys
import xlwt
import datetime
import local
import json

API_KEY = 'dda4c35828204f0246c88e943a63f79bb7b472c220d5c512281a6ded2ea3f121'

year = sys.argv[1]
zip_dir = os.path.join('files', year)
extracted_dir = os.path.join(zip_dir, 'extracted')
extension = ".zip"




def check_vt(file_path):
    resource = get_resource(file_path)
    if resource is not None:
        params = {'apikey': API_KEY, 'resource': resource}
        headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"
         }
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
        params=params, headers=headers)
        try:
            json_response = response.json()    
            rate = str(json_response['positives']) + "/" + str(json_response['total'])
            ws.write(line_counter, 2, rate)
            scans = json_response['scans']
            ws.write(line_counter, 3, check_cve(scans))
        except KeyError:
            pass


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
                        ws.write(line_counter, 4, "Yes")
                        cve_list.append(cve)
    if cve_list:
        output = "/".join(cve_list)
    else :
        output = "None"
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
    try:
        json_response = response.json()
        resource = json_response['resource']
        return resource
    except ValueError:
        return None

def check_zip():
    for item in os.listdir(zip_dir):
        if item.endswith(extension):
            item_path = os.path.join(zip_dir, item)
            check_vt(item_path)
            time.sleep(60)

def check_swf():
    cve_count = 0
    for item in os.listdir(extracted_dir):
        new_dir = os.path.join(extracted_dir, item)
        print ("Inside ", new_dir)
        global line_counter
        line_counter += 1
        ws.write(line_counter, 0, item)
        file_counter = 0
        for file in os.listdir(new_dir):
            if os.path.isfile(os.path.join(new_dir, file)):
                if file.endswith(".swf") or file.endswith(".exe") or file.endswith(".hta") or file.endswith(".zip") or file.endswith(".xap") or file.endswith(".dll") or file.endswith(".txt"):
                    print ("File: ", file, "Time:", datetime.datetime.now())
                    file_counter += 1
                    if (file_counter > 1):
                        line_counter += 1
                    ws.write(line_counter, 1, file)
                    item_path = os.path.join(new_dir, file)
                    if file.endswith(".swf"): 
                        #local.create_as(item_path)
                        as_folder = os.path.splitext(item_path)[0]
                        script_path = os.path.join(as_folder, "scripts")
                        if local.check_2015_8651(script_path):
                            cve_count += 1
                            ws.write(line_counter, 5, "CVE-2015-8651")
                    check_vt(item_path)
                    time.sleep(60)
    print ("cve", cve_count)
    print ("FINISHED")
def write_lables():
    ws.write(0, 0, "Folder")
    ws.write(0, 1, "File")
    ws.write(0, 2, "General Detection Rate")
    ws.write(0, 3, "CVE Detected")
    ws.write(0, 4, "Conflict Detected")
    ws.write(0, 5, "Local")

#check_zip()
#sys.stdout = open("vt_result.txt","w")
wb = xlwt.Workbook()
ws = wb.add_sheet('A Test Sheet')#, cell_overwrite_ok=True)
line_counter = 0
write_lables()
check_swf()
file_name = year + "_all.xlsx"
wb.save(file_name)

#sys.stdout.close()
