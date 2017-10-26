import requests
import re
from six.moves import urllib
import os
import time
from xml.dom import minidom
from bs4 import BeautifulSoup

rss_url = 'http://malware-traffic-analysis.net/blog-entries.rss'
year = 2017
url_prefix = 'http://malware-traffic-analysis.net/' + str(year) + '/'
page_url = url_prefix + 'index.html'
rss_file = 'blog-entries.rss'
url_filter = '(malware|artifacts).*\.zip'

API_KEY = 'dda4c35828204f0246c88e943a63f79bb7b472c220d5c512281a6ded2ea3f121'

def get_zip_files(url):
    html = requests.get(url).content
    soup = BeautifulSoup(html, "lxml")

    for a in soup.find_all('a', href=True):
        href = a['href']
        if re.search(url_filter, href):
            yield href

def get_links(url):
    return resolve_links((link for link in requests.get(url).content.xpath('//a/@href')))

def guess_root(links):
    for link in links:
        if link.startswith('http'):
            parsed_link = urlparse.urlparse(link)
            scheme = parsed_link.scheme + '://'
            netloc = parsed_link.netloc
            return scheme + netloc

def resolve_links(links):
    root = guess_root(links)
    for link in links:
        if not link.startswith('http'):
            link = urlparse.urljoin(root, link)
        yield link

def parse_rss(url):
    r = requests.get(url)
    open(rss_file, 'wb').write(r.content)
    print('Wrote ' + rss_file)
    print('Parsing...')

    xmldoc = minidom.parse(rss_file)
    item_list = xmldoc.getElementsByTagName('title')

    for title in item_list:
        value = title.childNodes[0].nodeValue
        if('EK' in value):
            link = title.parentNode.getElementsByTagName('link')[0].childNodes[0].nodeValue
            zips = ','.join(get_zip_files(link))
            print(value + "\t" + link + "\t" + zips)


eks = ['Rig','Magnitude', 'Terror', 'Sundown', 'Kaixin', 'Nebula', 'Neutrino', 'Angler']

def get_ek(text):
    for ek in eks:
        if ek.lower() in text.lower(): return ek

    return None

def check_vt(file_name):
    resource = get_resource(file_name)
    params = {'apikey': API_KEY, 'resource': resource}
    headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  My Python requests library example client or username"
     }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
    params=params, headers=headers)
    json_response = response.json()
    try:
        print ("result: ", json_response['positives'] , "/" ,  json_response["total"])
    except Exception:
        pass

def get_resource(file_name):
    params = {'apikey': API_KEY }
    file_path = os.path.join("files", file_name)
    files = {'file': (file_name, open(file_path, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    resource = json_response['resource']
    return resource

def parse_page(url):
    counts = {}
    html = requests.get(url).content
    soup = BeautifulSoup(html, "lxml")
    print('Parsing...')

    for a in soup.find_all('a', href=True, attrs={"class" : "main_menu"}):
        value = a.text
        #if 'class' in a:
        #    class_name = a['class']
        #else:
        #    class_name = None
        #print (a)class_name == 'main_menu' and
        if 'EK' in value:
            ek = get_ek(value)
            if ek:

                date_index = a['href']
                link = url_prefix + date_index
                index = date_index.rfind('/')
                date = date_index[0:index]
                zip_prefix = url_prefix + date
                
                unique_zips = list(set(get_zip_files(link)))
                zips = ','.join(unique_zips)
                print(date + "\t" + ek + "\t" + value + "\t" + zips)


                testfile = urllib.request.URLopener()
                
                if not os.path.exists("files"):
                  os.makedirs("files")
                  
                for zip in unique_zips:
                    zip_link = zip_prefix + '/' + zip
                    destination = "files/" + zip
                    testfile.retrieve(zip_link, destination)
                    check_vt(zip)

                print ("- - - - - - - - - - - - ")
                time.sleep(60)
                if ek in counts:
                    counts[ek] = counts[ek] + 1
                else:
                    counts[ek] = 1
            else:
                print ("...Skipping " +value + ',' + link)

    return counts

print('EK stats')
counts = parse_page(page_url)
for key, value in sorted(counts.items()):
    print("{} : {}".format(key, value))
