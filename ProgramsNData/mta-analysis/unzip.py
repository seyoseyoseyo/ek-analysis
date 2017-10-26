import os, zipfile

dir_name = 'files'
extension = ".zip"

unzipped_path = dir_name + "/" + "extracted"
if not os.path.exists(unzipped_path):
  os.makedirs(unzipped_path)

# os.chdir(dir_name) # change directory from working dir to dir with files

for item in os.listdir(dir_name): # loop through items in dir
    if item.endswith(extension): # check for ".zip" extension
        file_path = dir_name + "/" + item
        file_name = os.path.splitext(item)[0]
        extracted_path = unzipped_path + "/" + file_name
        # file_name = os.path.abspath(item) # get full path of files
        zip_ref = zipfile.ZipFile(file_path) # create zipfile object
        zip_ref.extractall(extracted_path, pwd = "infected") # extract file to dir
        zip_ref.close() # close file

