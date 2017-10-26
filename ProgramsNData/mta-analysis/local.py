import os

jar_path = os.path.join("C:\Program Files (x86)\FFDec", "ffdec.jar")

def create_as(file_path):
    file_name = os.path.basename(file_path)
    as_path = os.path.splitext(file_path)[0]
    statement = "java -jar " + "\""+ jar_path + "\"" + " -export script " + as_path + " " + file_path
    cwd = os.getcwd()
    #java -jar ffdec.jar -export script "C:\decompiled" myfile.swf
    os.system(statement)

def check_2015_8651(script_path):
    detected = False
    for file in os.listdir(script_path):
        if file.endswith(".as"):
            file_path = os.path.join(script_path, file)
            with open(file_path, 'r', encoding = "utf8") as myfile:
                data = myfile.read()
                if "2147483644" in data:
                #if data.count("2147483644") >= 3:
                    detected = True
                    print ("------")
                    print (data)
                    print ("------")
                    
    return detected