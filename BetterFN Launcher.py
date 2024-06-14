import tkinter
import customtkinter
import psutil
import os
import time
import hashlib
import sys
import tkinter.messagebox as mbox
import json
from io import BytesIO
import subprocess
import requests
import webbrowser
import threading
from PIL import Image, ImageTk

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")


class DLLInjector:
    def __init__(self, pid, dll_path):
        self.pid = pid
        self.dll_path = dll_path

    def download_file(self, url, destination_path):
        response = requests.get(url)
        if response.status_code == 200:
            with open(destination_path, 'wb') as file:
                file.write(response.content)
            print(f"File downloaded successfully to {destination_path}")
        else:
            print(f"Failed to download file. Status code: {response.status_code}")

    def inject_dll(self):
        try:
            injector_path = os.path.join(os.getcwd(), "Injector", "injector.exe")
            if not os.path.exists(injector_path):
                print("Injector Not Found! Downloading...")
                self.download_file("http://147.135.119.47:9912/api/download?name=injector.exe", injector_path)
                while not os.path.exists(injector_path):
                    time.sleep(1.5)
                print("Download Complete!")
            else:
                print("Injector Found! Injecting...")
            os.system(f'{injector_path} "{self.pid}" "{self.dll_path}"')
        except Exception as e:
            print(f"Error while injecting DLL: {e}")

class FreeGameLauncher:
    def __init__(self, app):
        self.app = app
        self.PROGRAMDATA = os.environ.get('PROGRAMDATA', '')
        self.loginDataa = None

    def clear_widgets(self, app=None):
        if app is None:
            app = self.app
        for widget in app.winfo_children():
            widget.destroy()

    def startLaunch(self):
        cwd = os.getcwd()
        path = os.path.join(cwd, "Saved", "loginData.json")
        if os.path.exists(path):
            with open(path, 'r') as f:
                self.loginDataa = json.load(f)
        else:
            self.clear_widgets()
            print("Fatal error: LoginData.json does NOT exist!")
            return

        self.getLoginCode()

    def getLoginCode(self):
        if self.loginDataa is None:
            self.clear_widgets()
            print("Fatal error: LoginData.json does NOT exist!")
            return
        headers = {
            'Authorization': 'Basic OThmN2U0MmMyZTNhNGY4NmE3NGViNDNmYmI0MWVkMzk6MGEyNDQ5YTItMDAxYS00NTFlLWFmZWMtM2U4MTI5MDFjNGQ3',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        body = {
            "grant_type": 'device_auth',
            "account_id": self.loginDataa['accountId'],
            "device_id": self.loginDataa['deviceId'],
            "secret": self.loginDataa['secret'],
            "token_type": 'eg1'
        }
        response = requests.post("https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", headers=headers, data=body)
        if response.status_code != 200:
            self.clear_widgets()
            print("Fatal error: failed to fetch accessToken!")
            return
        self.loginDataa['accessToken'] = response.json()['access_token']
        headers = {
            'Authorization': f"Bearer {self.loginDataa['accessToken']}"
        }
        response = requests.get("https://account-public-service-prod.ol.epicgames.com/account/api/oauth/exchange", headers=headers)
        reqjson = response.json()
        if response.status_code != 200:
            self.clear_widgets()
            print("Fatal error: failed to fetch exchange!")
            return
        print(reqjson)
        self.loginDataa['exchange'] = reqjson['code']
        self.launch_fortnite()

    def inject(self, dllPath):
        pid = self._get_process_pid('FortniteClient-Win64-Shipping.exe')
        if not pid:
            return

        path = os.path.join(os.getcwd(), "DLLs", "BFN.dll")
        if not os.path.exists(path):
            print("BFN.dll Not Found! Downloading...")
            self.download_file("http://147.135.119.47:9912/api/download?name=BFN.dll", path)
            while not os.path.exists(path):
                time.sleep(1.5)
            print("Download Complete!")

        try:
            time.sleep(2.5)
            DLLInjector(pid, dllPath).inject_dll()
        except Exception as e:
            print(f"Error while injecting BFN.dll: {e}")

    def afterLaunched(self):
        path = self.get_path()
        self.kill_process_by_name("FortniteLauncher.exe")
        print("Killed")
        launcher_path = os.path.join(path, "FortniteGame", "Binaries", "Win64")
        old_launcher = os.path.join(launcher_path, "FortniteLauncher1.exe")
        new_launcher = os.path.join(launcher_path, "FortniteLauncher.exe")

        if os.path.exists(new_launcher):
            os.remove(new_launcher)
        os.rename(old_launcher, new_launcher)
        print("Undone ac bypass")

        dllPath = os.path.join(os.getcwd(), "DLLs", "BFN.dll")
        self.inject(dllPath)

    def acBypass(self):
        path = self.get_path()
        launcher_path = os.path.join(path, "FortniteGame", "Binaries", "Win64")
        old_launcher = os.path.join(launcher_path, "FortniteLauncher1.exe")
        new_launcher = os.path.join(launcher_path, "FortniteLauncher.exe")

        if os.path.exists(old_launcher):
            if os.path.exists(new_launcher):
                os.remove(new_launcher)
            os.rename(old_launcher, new_launcher)
            print("Fortnite Launcher crash fixed.")

    def launch_fortnite(self):
        self.acBypass()
        path = os.path.join(self.get_path(), "FortniteGame", "Binaries", "Win64")
        launcher_exe = os.path.join(path, "FortniteLauncher.exe")
        new_launcher_exe = os.path.join(path, "FortniteLauncher1.exe")

        if os.path.exists(launcher_exe):
            try:
                os.rename(launcher_exe, new_launcher_exe)
                self.download_file("http://147.135.119.47:9912/api/download?name=FortniteLauncher.exe", launcher_exe)
            except FileExistsError:
                self.display_error_message("Failed to bypass anticheat, please contact support.")
                return
        else:
            self.display_error_message(f"Could not find FortniteLauncher.exe in your current path, {launcher_exe}")
            return

        self.kill_process_by_name("FortniteClient-Win64-Shipping_EAC_EOS.exe")
        command = f'start "Game Launcher" /d "{path}" FortniteLauncher.exe -AUTH_LOGIN=unused -AUTH_PASSWORD={self.loginDataa["exchange"]} -AUTH_TYPE=exchangecode -epicapp=Fortnite -epicenv=Prod -EpicPortal -epicuserid={self.loginDataa["accountId"]}'
        subprocess.run(command, shell=True)

        self.wait_for_fortnite()

    def wait_for_fortnite(self):
        print("Waiting for Fortnite to launch...")
        fortnite_process_name = "FortniteClient-Win64-Shipping.exe"
        while not any(proc.name() == fortnite_process_name for proc in psutil.process_iter()):
            time.sleep(1)
        print("Fortnite Detected, Hooking DLLs...")
        self.app.after(1500, self.afterLaunched)

    def download_file(self, url, destination_path):
        response = requests.get(url)
        if response.status_code == 200:
            with open(destination_path, 'wb') as file:
                file.write(response.content)
            print(f"File downloaded successfully to {destination_path}")
        else:
            print(f"Failed to download file. Status code: {response.status_code}")

    def kill_process_by_name(self, process_name):
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'] == process_name:
                try:
                    psutil.Process(process.info['pid']).terminate()
                    process.wait(timeout=5)
                    print(f"Process {process_name} terminated")
                    return
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"Error terminating process: {e}")
                except Exception as e:
                    print(f"Unexpected error: {e}")

    def get_path(self):
        launcher_installed = os.path.join(self.PROGRAMDATA, "Epic", "UnrealEngineLauncher", "LauncherInstalled.dat")
        with open(launcher_installed, 'r') as f:
            installations = json.load(f)["InstallationList"]
            for installation in installations:
                if installation["AppName"] == "Fortnite":
                    return installation["InstallLocation"].replace("/", "\\")
        return None

    def display_error_message(self, message):
        mbox.showerror("Error", message)

    def _get_process_pid(self, process_name):
        for process in psutil.process_iter(['name']):
            if process.info['name'] == process_name:
                return process.pid
        return None

class LauncherApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("BetterFN Launcher")
        self.geometry(f"600x375")
        self.resizable(False, False)
        self.gameLauncherClient = FreeGameLauncher(self)

        self.Page_1 = self.create_page()
        self.Page_2 = self.create_page()
        
        self.create_frame(self.Page_1, 0, 0)
        self.create_label(self.Page_1, "Launcher", 261, 3, 62)
        self.create_button(self.Page_1, "Launcher", 6, 61, self.Page_1)
        self.create_frame(self.Page_1, 126, 302, 474, 73)
        self.create_button(self.Page_1, "Launch BFN!", 353, 311, command=self.gameLauncherClient.startLaunch, width=232, height=44, font_size=46)
        self.create_button(self.Page_1, "Premium", 6, 105, self.Page_2)
        self.create_label(self.Page_1, "BFN", 22, 0, 61)
        self.create_image_button(self.Page_1, "Join us on discord!", 242, 80, "Assets/discord.png", "https://discord.gg/pxkjQJvQUv")

        self.create_frame(self.Page_2, 0, 0)
        self.create_label(self.Page_2, "Premium", 261, 3, 62)
        self.create_button(self.Page_2, "Launcher", 6, 61, self.Page_1)
        self.create_frame(self.Page_2, 126, 302, 474, 73)
        self.create_button(self.Page_2, "Premium", 6, 105, self.Page_2)
        self.create_label(self.Page_2, "BFN", 22, 0, 61)
        self.create_label(self.Page_2, "Coming Soon!", 234, 97, 54)

        self.switch_page(self.Page_1)

    def create_page(self):
        page = customtkinter.CTkFrame(self, fg_color='transparent', corner_radius=0, border_width=0)
        return page

    def create_frame(self, page, x, y, width=129, height=375):
        frame = customtkinter.CTkFrame(page, width=width, height=height, corner_radius=0, fg_color="#1e1e1e", bg_color=['gray92', 'gray14'])
        frame.place(x=x, y=y)

    def create_label(self, page, text, x, y, font_size):
        label = customtkinter.CTkLabel(page, bg_color=['gray92', 'gray14'], font=customtkinter.CTkFont('Burbank BIg Cd Bk', size=font_size, weight='bold'), text=text)
        label.place(x=x, y=y)

    def create_button(self, page, text, x, y, switch_page=None, command=None, width=115, height=31, font_size=31):
        button = customtkinter.CTkButton(
            page, bg_color="#1e1e1e", width=width, height=height, corner_radius=11, text=text, fg_color="#6a728e", hover_color="#144870",
            command=command or (lambda: self.switch_page(switch_page)), font=customtkinter.CTkFont('Burbank BIg Cd Bk', size=font_size)
        )
        button.place(x=x, y=y)

    def create_image_button(self, page, text, x, y, img_path, url):
        img = customtkinter.CTkImage(Image.open(img_path), size=(126, 108))
        button = customtkinter.CTkButton(
            page, bg_color="#242424", width=0, height=0, corner_radius=11, text=text, fg_color="transparent", hover_color="#02090d",
            command=lambda: self.open_site(url), font=customtkinter.CTkFont('Burbank Big Cd Bk', size=31), image=img, compound="top", hover=False
        )
        button.place(x=x, y=y)

    def switch_page(self, page):
        for p in [self.Page_1, self.Page_2]:
            p.pack_forget()
        page.pack(expand=True, fill='both')

    def open_site(self, url):
        webbrowser.open(url)





class authApp(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("BetterFN Launcher | Login to your account.")
        height = 375
        width = 1000
        self.geometry(f"{width}x{height}")
        self.resizable(False, False)
        self.app = self
        self.startThing()

    def startThing(self):
        cwd = os.getcwd()
        path = os.path.join(cwd, "Saved", "loginData.json")
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.load(f)
                if data.get("accountId") and data.get("deviceId") and data.get('secret'):
                    self.clear_widgets()
                    label = customtkinter.CTkLabel(self, text=f"Welcome back {data['displayName']}!", font=("Burbank", 24, "bold"))
                    label.pack(padx=10, pady=10)
                    authBtn = customtkinter.CTkButton(self, text="Continue", font=customtkinter.CTkFont("Burbank", 14, "bold"), command=lambda event=None: self.continueBtnCallback())
                    authBtn.pack(padx=10, pady=10)
                    resaveBtn = customtkinter.CTkButton(self, text="Resave auth", font=("Burbank", 14, "bold"), command=lambda event=None: self.resave())
                    resaveBtn.pack(padx=10, pady=10)
                if data == {}:
                    self.mainAuth()

    def resave(self):
        cwd = os.getcwd()
        path = os.path.join(cwd, "Saved", "loginData.json")
        if os.path.exists(path):
            with open(path, "w") as f:
                json.dump({}, f)
        else:
            print("File does not exist.")
        self.mainAuth()

    def mainAuth(self):
        self.clear_widgets()
        label = customtkinter.CTkLabel(self, text="Please login to your Fortnite account that you would like to use for BFN.", font=customtkinter.CTkFont('Burbank', 24, "bold"))
        label.pack(padx=10, pady=10)

        authBtn = customtkinter.CTkButton(self, text="Login", font=customtkinter.CTkFont("Burbank", 14, "bold"), command=lambda event=None: self.login())
        authBtn.pack(padx=10, pady=10)

    def open_site(self, url):
        webbrowser.open(url)

    def login(self):
        self.clear_widgets()
        
        headers = {
            'Authorization': 'basic OThmN2U0MmMyZTNhNGY4NmE3NGViNDNmYmI0MWVkMzk6MGEyNDQ5YTItMDAxYS00NTFlLWFmZWMtM2U4MTI5MDFjNGQ3',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = "grant_type=client_credentials"
        
        req = requests.post("https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", headers=headers, data=payload)
        jsonrq = req.json()
        deviceauth_headers = {
            "Authorization": "bearer " + jsonrq['access_token'],
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        deviceauth_payload = {"prompt": "login"}
        
        deviceauth_req = requests.post("https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/deviceAuthorization", headers=deviceauth_headers, json=deviceauth_payload)
        deviceauth_jsonrq = deviceauth_req.json()

        self.devicecode = deviceauth_jsonrq['device_code']
        self.stopped = False
        self.open_site(deviceauth_jsonrq['verification_uri_complete'])

        waitingLabel = customtkinter.CTkLabel(self, text="Waiting for authentication...", font=("Burbank", 24, "bold"))
        waitingLabel.pack(padx=10, pady=10)

        self.interval_thread = threading.Thread(target=self.check_auth_status)
        self.interval_thread.start()

        self.timeout_thread = threading.Timer(120, self.stop_checking)
        self.timeout_thread.start()

    def check_auth_status(self):
        while not self.stopped:
            try:
                response = requests.post("https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", data={
                    'grant_type': 'device_code',
                    'device_code': self.devicecode,
                    'token_type': 'eg1'
                }, headers={
                    'Authorization': 'Basic OThmN2U0MmMyZTNhNGY4NmE3NGViNDNmYmI0MWVkMzk6MGEyNDQ5YTItMDAxYS00NTFlLWFmZWMtM2U4MTI5MDFjNGQ3',
                    'Content-Type': 'application/x-www-form-urlencoded'
                })

                self.loggedindata = response.json()
                if response.status_code == 200:
                    print(self.loggedindata)
                    self.rqstatus = 1
                    self.stopped = True

                    self.clear_widgets()
                    successLabel = customtkinter.CTkLabel(self, text="Successfully authenticated account.", font=("Burbank", 24, "bold"))
                    successLabel.pack(padx=10, pady=10)

                    deviceauths_response = requests.post(f"https://account-public-service-prod.ol.epicgames.com/account/api/public/account/{self.loggedindata['account_id']}/deviceAuth", headers={
                        'Authorization': f"Bearer {self.loggedindata['access_token']}"
                    })
                    deviceauths_data = deviceauths_response.json()
                    if self.rqstatus != 1:
                        return

                    accid = deviceauths_data['accountId']
                    deviceid = deviceauths_data['deviceId']
                    secret = deviceauths_data['secret']
                    self.rqstatus = 2
                    data = {
                        "accountId": accid,
                        "deviceId": deviceid,
                        "secret": secret,
                        "displayName": self.loggedindata['displayName'],
                    }
                    cwd=os.getcwd()
                    savingPath = os.path.join(cwd, "Saved", "loginData.json")
                    with open(savingPath, 'w+') as f:
                        f.write(json.dumps(data, indent=4))

    
                    grant_access_response = requests.post(f"https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/grant_access/{accid}", headers={
                        'Authorization': f"Bearer {self.loggedindata['access_token']}"
                    })

                    if grant_access_response.status_code == 200:
                        print("Accepted elua")
                    elif grant_access_response.json().get('errorCode') == "errors.com.epicgames.bad_request":
                        print("Account already accepted elua")
                    else:
                        print(grant_access_response.json())
                        return

                    self.clear_widgets()
                    successLabel = customtkinter.CTkLabel(self, text=f"Successfully saved account: {self.loggedindata["displayName"]}", font=("Burbank", 24, "bold"))
                    successLabel.pack(padx=10, pady=10)
                    continueBtn = customtkinter.CTkButton(self, text="Continue", font=("Burbank", 14, "bold"), command=lambda event=None: self.continueBtnCallback())
                    continueBtn.pack(padx=10, pady=10)
                elif self.loggedindata.get('errorCode') == "errors.com.epicgames.not_found":
                    self.clear_widgets()
                    canceledLabel = CTkLabel(self, text="Login Canceled. Your Login request was canceled.", font=("Burbank", 24, "bold"), fg_color='Red')
                    canceledLabel.pack(padx=10, pady=10)
                    self.stopped = True
                    return

                
            except Exception as e:
                print('Error executing code:', e)

            time.sleep(5)

    
    def continueBtnCallback(self):
        self.destroy()
        newApp = LauncherApp()
        newApp.mainloop()
    def stop_checking(self):
        self.stopped = True
        self.clear_widgets()
        expiredLabel = CTkLabel(self, text="Expired. Your Login has canceled", font=("Burbank", 24, "bold"), fg_color='Red')
        expiredLabel.pack(padx=10, pady=10)



    def clear_widgets(self, app=None):
        if app == None:
            app = self.app
        for widget in app.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    AuthApp = authApp()
    AuthApp.mainloop()