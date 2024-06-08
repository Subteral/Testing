import os
import time
import random
import base64
import json

import threading
import requests
import loguru
import modules.capbypass

from colorama import Fore, Back, Style
from datetime import datetime, timezone
from random_username.generate import generate_username

settings_json = json.loads(open("settings.json", "r").read())

def color(text: str, fg, bg=None):
    colored_text = f'{fg}{text}{Style.RESET_ALL}'

    return colored_text if bg is None else bg + colored_text

class AccountGen:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            "authority": "www.roblox.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "pragma": "no-cache",
            "sec-ch-ua": '"Not_A Brand";v="9", "Chromium";v="125", "Brave";v="125"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "sec-gpc": "1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        }

        self.proxy = random.choice(open("proxy.txt", "r").readlines()).strip()
        self.session.proxies = {
            "http": "http://" + self.proxy.strip(),
            "https": "http://" + self.proxy.strip(),
        }

        self.account_passw = "TestPassword12345!"

    def get_csrf(self):
        self.session.headers["authority"] = "www.roblox.com"
        response = self.session.get("https://www.roblox.com/home")

        self.csrf_token = response.text.split('"csrf-token" data-token="')[1].split(
            '"'
        )[0]
        print('Retrieved CSRF Token:', color(self.csrf_token, Fore.RED))
        time.sleep(2)
        print(f'{color('Setting x-csrf-token Header', Fore.GREEN)}')
        self.session.headers["x-csrf-token"] = self.csrf_token
        print(color(self.session.headers, Fore.BLUE))
        time.sleep(2)

    def generate_birthday(self):
        birthdate = (
            datetime(
                random.randint(1990, 2006),
                random.randint(1, 12),
                random.randint(1, 28),
                21,
                tzinfo=timezone.utc,
            )
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        return birthdate

    def verify_username(self):
        self.session.headers["authority"] = "auth.roblox.com"
        self.session.headers["accept"] = "application/json, text/plain, */*"

        self.birthdate = self.generate_birthday()
        print('Generated Birthday:', color(self.birthdate, Fore.GREEN))
        time.sleep(1)
        nickname = generate_username(1)[0]+str(random.randint(10,99)) # Add ability for custom usernames ex: rookie_(2)_(3) depending on settings
        print('Generated Nickname:', color(nickname, Fore.GREEN))
        time.sleep(1)
        print('Password:', color(self.account_passw, Fore.GREEN))

        response = self.session.get(
            f"https://auth.roblox.com/v1/validators/username?Username={nickname}&Birthday={self.birthdate}",
        )

        try:
            self.nickname = random.choice(response.json()["suggestedUsernames"])
        except:
            self.nickname = nickname

    def signup_request(self):
        json_data = {
            "username": self.nickname,
            "password": self.account_passw,
            "birthday": self.birthdate,
            "gender": 2,
            "isTosAgreementBoxChecked": True,
            "agreementIds": [
                "adf95b84-cd26-4a2e-9960-68183ebd6393",
                "91b2d276-92ca-485f-b50d-c3952804cfd6",
            ],
            "secureAuthenticationIntent": {
                "clientPublicKey": "roblox sucks",
                "clientEpochTimestamp": str(time.time()).split(".")[0],
                "serverNonce": self.serverNonce,
                "saiSignature": "lol",
            },
        }

        response = self.session.post(
            "https://auth.roblox.com/v2/signup", json=json_data
        )

        return response


    def generate_account(self):
        self.session.headers["authority"] = "apis.roblox.com"
        response = self.session.get(
            "https://apis.roblox.com/hba-service/v1/getServerNonce"
        )
        print(f'{color('Retrieving Server Nonce', Fore.GREEN)}')
        self.serverNonce = response.text.split('"')[1]
        time.sleep(2)
        print(color(self.serverNonce, Fore.BLUE))

        self.session.headers["authority"] = "auth.roblox.com"

        response = self.signup_request()

        if "Token Validation Failed" in response.text:
            print(color("Token Validation Failed, Setting Token.", Fore.RED))
            self.session.headers["x-csrf-token"] = response.headers["x-csrf-token"]
            response = self.signup_request()
        if response.status_code == 429:
            loguru.logger.error("ip ratelimit, retrying..")
            return ""
        
        print(color("Retrieving Captcha Data.", Fore.GREEN))

        captcha_response = json.loads(
            base64.b64decode(
                response.headers["rblx-challenge-metadata"].encode()
            ).decode()
        )

        time.sleep(1)

        unifiedCaptchaId = captcha_response["unifiedCaptchaId"]
        print('unifiedCaptchaId:', color(unifiedCaptchaId, Fore.BLUE))
        dataExchangeBlob = captcha_response["dataExchangeBlob"]
        print('dataExchangeBlob:', color(dataExchangeBlob, Fore.BLUE))
        genericChallengeId = captcha_response["sharedParameters"]["genericChallengeId"]
        print('genericChallengeId:', color(genericChallengeId, Fore.BLUE))
        time.sleep(1)

        print(color("Solving Captcha.", Fore.GREEN))
        time.sleep(1)
        print('Chosen Proxy:', color(self.proxy, Fore.BLUE))

        solver = modules.capbypass.Solver(settings_json["capbypass_key"])
        captcha_solution = solver.solve(dataExchangeBlob, self.proxy)
        print(captcha_solution)
        if captcha_solution == False:
            return ""

        self.session.headers["authority"] = "apis.roblox.com"
        print(self.session)

        json_data = {
            "challengeId": genericChallengeId,
            "challengeType": "captcha",
            "challengeMetadata": json.dumps(
                {
                    "unifiedCaptchaId": genericChallengeId,
                    "captchaToken": captcha_solution,
                    "actionType": "Signup",
                }
            ),
        }

        self.session.post(
            "https://apis.roblox.com/challenge/v1/continue", json=json_data
        )

        self.session.headers["rblx-challenge-id"] = unifiedCaptchaId
        self.session.headers["rblx-challenge-type"] = "captcha"
        self.session.headers["rblx-challenge-metadata"] = base64.b64encode(
            json.dumps(
                {
                    "unifiedCaptchaId": unifiedCaptchaId,
                    "captchaToken": captcha_solution,
                    "actionType": "Signup",
                }
            ).encode()
        ).decode()

        resp = self.signup_request()
        print(resp)
        print(resp.text)
        try:
            cookie = resp.cookies[".ROBLOSECURITY"]
            print(cookie)
        except:
            loguru.logger.error("capbypass gives us wrong captcha token 😡..")
            return ""
        self.userid = resp.json()["userId"]
        loguru.logger.info(f"[https://www.roblox.com/users/{self.userid}] account created!")

    def chooseamount(self):
        generate_count = input("How many accounts do you want to generate?: ")
        self.generate(generate_count)

    # Add multi account later
    def generate(self, generate_count):
        while True:
            try:
                gen = AccountGen()
                gen.get_csrf()
                gen.verify_username()
                gen.generate_account()
                break
            except KeyError as E:
                loguru.logger.error(f"{E},retrying.")
                pass
            except Exception as E:
                loguru.logger.error(E)
                break
    
class FollowBot:
    def __init__(self):
        pass
    
    def run(self):
        print("Follow Bot")
        follow_id = input("What is the userid of the player you want to follow?: ")

class GroupBot:
    def __init__(self):
        pass
    
    def run(self):
        print("Group Bot")
        group_id = input("What is the groupid of the group you want to join?: ")

class SettingsManager:
    def __init__(self):
        pass

    def load_settings(self):
        print("Settings.")
        time.sleep(5)

class Menu:
    def __init__(self):
        self.account_gen = AccountGen()
        self.follow_bot = FollowBot()
        self.group_bot = GroupBot()
        self.settings_manager = SettingsManager()

    def clear_screen(self):
        if os.name == 'nt':  # Windows
            os.system('cls')
        else:  # macOS / Linux
            os.system('clear')

    def display_menu(self):
        while True:
           # self.clear_screen()
            print("Menu:")
            print("1. Account Generator")
            print("2. Follow Bot")
            print("3. Group Bot")
            print("4. Settings")
            print("5. Exit")
            choice = input("Choose an option (1-5): ")

            #self.clear_screen() ## Removing clr so i can see output for testing.
            
            if choice == '1':
                self.account_gen.chooseamount()
            elif choice == '2':
                self.follow_bot.run()
            elif choice == '3':
                self.group_bot.run()
            elif choice == '4':
                self.settings_manager.load_settings()
            elif choice == '5':
                break
            else:
                print("Invalid choice, please select a number between 1 and 5.")
                time.sleep(2)

if __name__ == "__main__":
    menu = Menu()
    menu.display_menu()