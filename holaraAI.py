import requests
import base64
import json
from bs4 import BeautifulSoup
import re
import random
import math


class OriginalBool:
    def __init__(self, v:bool=True, messages:list[str, str]=["true", "false"]):
        self._value = v
        self._messages = messages

    def setMessage(self, msg:list[str, str]):
        self._messages = msg

    def setBool(self, v:bool):
        self._value = v

    def __bool__(self):
        return self._value

    def __str__(self):
        return str(self._messages[0]) if self._value else str(self._messages[1])

    @property
    def v(self) -> str:
        return self._messages[0] if self._value else self._messages[1]


class holara:
    def __init__(self):
        self.session = requests.Session()

        self.session.headers = {
            'authority': 'holara.ai',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'accept-language': 'ja;q=0.7',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://holara.ai',
            'sec-ch-ua': '"Brave";v="113", "Chromium";v="113", "Not-A.Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'sec-gpc': '1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        }

    def csrf(self, url:str="https://holara.ai/") -> str:
        res = self.session.get(url)
        if res.status_code == 200:
            if 'name="csrfmiddlewaretoken" value="' in res.text:
                return res.text.split('name="csrfmiddlewaretoken" value="')[1].split('"')[0]
            return res.cookies.get("csrftoken")
        else:
            raise Exception("Failed to get CSRF token")

    def _decodeMessage(self, content:str):
        jsonRaw = base64.b64decode(content)
        try:
            messages = json.loads(jsonRaw)
            return messages
        except:
            return jsonRaw

    def _getError(self, ob:OriginalBool, defaultMsg:list, response:requests.Response) -> OriginalBool:
        if response.status_code == 403:
            defaultMsg[1] = "403 Forbidden"
            ob.setBool(False)
            ob.setMessage(defaultMsg)
        elif "invalid-feedback" in response.text:
            html = BeautifulSoup(response.text, "html.parser")
            errorContents = ""
            for elem in html.find_all("p", class_="invalid-feedback"):
                errorContents += elem.find("strong").text+"\n"
            defaultMsg[1] = errorContents
            ob.setMessage(defaultMsg)
        elif response.status_code!= 200:
            defaultMsg[1] = f"Unexpected Errors (status={response.status_code})"
            ob.setMessage(defaultMsg)

    def _permission(self) -> OriginalBool:
        if "sessionid" not in self.session.cookies:
            raise Exception("Please login")

    def register(self, email:str, password:str) -> OriginalBool:
        csrf = self.csrf("https://holara.ai/accounts/signup/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'email': email,
            'password1': password,
        }
        self.session.cookies["csrftoken"] = csrf

        res = self.session.post('https://holara.ai/accounts/signup/', data=data)

        defaultMsg = ["Successfully registered", "Failed to register"]

        ob = OriginalBool(True, defaultMsg)
        if res.url == 'https://holara.ai/accounts/confirm-email/':
            #res.cookies.get("messages")

            if res.cookies.get("messages"):
                messageContent = self._decodeMessage(res.cookies.get("messages"))
                if type(messageContent) == list:
                    defaultMsg[0] = messageContent[0]
                    ob.setMessage(defaultMsg)
                else:
                    defaultMsg[0] = "Confirmation e-mail sent to" + messageContent.split("Confirmation e-mail sent to")[1].split('",')[0]
                    ob.setMessage(defaultMsg)
            else:
                defaultMsg[0]
        else:
            ob.setBool(False)
            if res.status_code == 200:
                html = BeautifulSoup(res.text, "html.parser")
                errorElement = html.find_all("strong")[0]
                defaultMsg[1] = errorElement.text
                ob.setMessage(defaultMsg)

        return ob

    def confirmEmail(self, token:str) -> OriginalBool:
        url = f"https://holara.ai/accounts/confirm-email/{token}/"
        csrf = self.csrf(url)
        data = {
            'csrfmiddlewaretoken': csrf,
        }
        self.session.cookies["csrftoken"] = csrf

        res = self.session.post(url, data=data)

        defaultMsg = ["Successfully confirmed email \nYou can login using 'login(email, password)'", "Failed to confirm email"]

        ob = OriginalBool(True, defaultMsg)
        if res.url != 'https://holara.ai/':
            ob.setBool(False)
            if res.status_code == 200:
                defaultMsg[1] = "Confirm link expired"
                ob.setMessage(defaultMsg)

        return ob

    def login(self, email:str, password:str) -> OriginalBool:
        csrf = self.csrf("https://holara.ai/accounts/login/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'login': email,
            'password': password,
        }

        res = self.session.post('https://holara.ai/accounts/login/', data=data)

        defaultMsg = ["Successfully logged in", "Failed to login(error reason: null)"]

        ob = OriginalBool(True, defaultMsg)

        if res.url == 'https://holara.ai/':
            messageContent = self._decodeMessage(res.cookies.get("messages"))
            if type(messageContent) == list:
                defaultMsg[0] = self._decodeMessage(res.cookies.get("messages"))[0]
            else:
                defaultMsg[0] = "Successfully signed in" + self._decodeMessage(res.cookies.get("messages")).split("Successfully signed in")[1].split('"')[0]
            ob.setMessage(defaultMsg)
        else:
            ob.setBool(False)
            if res.status_code == 200:
                html = BeautifulSoup(res.text, "html.parser")
                errorContents = ""
                for elem in html.find_all("ul", class_="m-0"):
                    errorContents += elem.text+"\n"
                defaultMsg[1] = errorContents
                ob.setMessage(defaultMsg)

        return ob

    def Profile(self) -> OriginalBool:
        self._permission()
        res = self.session.get("https://holara.ai/accounts/profile/")

        defaultMsg = ["info", "Please login"]

        ob = OriginalBool(True, defaultMsg)

        if "/accounts/login/" in res.url:
            ob.setBool(False)
        else:
            html = BeautifulSoup(res.text, "html.parser")
            username_holder = html.find("div", {"id": "username-heading"})
            username = username_holder.find("div", class_="profile-user-attribute").text

            email_holder = html.find("div", {"id": "email-heading"})
            email = email_holder.find("div", class_="profile-user-attribute").text

            apiKey = html.find("span", {"id": "api-key"}).text
            defaultMsg[0] = {"username": username, "email": email, "apiKey": apiKey}
            ob.setMessage(defaultMsg)

        return ob

    def regenerateApiKey(self) -> OriginalBool:
        self._permission()

        csrf = self.csrf("https://holara.ai/accounts/profile/")
        data = {
            'csrfmiddlewaretoken': csrf,
        }

        defaultMsg = ["API_KEY", "Unexpected Errors"]

        ob = OriginalBool(True, defaultMsg)

        res = self.session.post('https://holara.ai/holara/api/1.0/regenerate_api_key', data=data)

        if res.status_code == 200:
            resJson = res.json()
            if resJson["status"] == "success":
                key = resJson["api_key"]
                defaultMsg[0] = key
            else:
                ob.setBool(False)
        elif res.status_code == 403:
            defaultMsg[1] = "403 Forbidden"
            ob.setBool(False)
            ob.setMessage(defaultMsg)
        else:
            defaultMsg[1] = f"Unexpected Errors (status={res.status_code})"
            ob.setBool(False)
            ob.setMessage(defaultMsg)

        return ob

    def DeletePromptHistory(self):
        self._permission()

        csrf = self.csrf("https://holara.ai/accounts/profile/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'delete-prompt-history-form-submit': '',
        }

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        defaultMsg = ["Successfully cleared", "Unexpected Errors"]

        ob = OriginalBool(True, defaultMsg)

        self._getError(ob, defaultMsg, res)

        return ob

    def ChangePassword(self, oldPassword:str, newPassword:str) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/accounts/profile/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'oldpassword': oldPassword,
            'password1': newPassword,
            'change-password-form-submit': '',
        }

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        defaultMsg = ["Password successfully changed.", "Failed to change password"]

        ob = OriginalBool(True, defaultMsg)

        self._getError(ob, defaultMsg, res)

        return ob

    def ChangeUsername(self, username:str) -> OriginalBool:
        self._permission()
        defaultMsg = ["Success! Username updated.", "Up to 150 characters, and only alphanumeric characters and ['@', '.', '+', '-', '_'] can be used"]
        ob = OriginalBool(True, defaultMsg)
        if not re.match(r"^[A-Za-z0-9@.+_-]+$", username):
            ob.setBool(False)
        if len(username) >= 150:
            ob.setBool(False)
        csrf = self.csrf("https://holara.ai/accounts/profile/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'username': username,
            'change-username-form-submit': '',
        }

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        self._getError(ob, defaultMsg, res)

        return ob

    def addEmail(self, email:str) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/accounts/profile/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'email': email,
            'add-email-form-submit': '',
        }

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        defaultMsg = ["Success! Username updated.", "Up to 150 characters, and only alphanumeric characters and ['@', '.', '+', '-', '_'] can be used"]
        ob = OriginalBool(True, defaultMsg)

        self._getError(ob, defaultMsg, res)

        return ob

    def resendEmail(self, email:str) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/accounts/profile/")
        data = {
            'csrfmiddlewaretoken': csrf,
            'email': email,
            'send-verification-email-form-submit': '',
        }

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        defaultMsg = [f"Confirmation e-mail sent to {email}", "Failed to send confirmation e-mail"]

        ob = OriginalBool(True, defaultMsg)

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        self._getError(ob, defaultMsg, res)

        return ob

    def setPrimaryMail(self, email:str) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/accounts/profile/")

        data = {
            'csrfmiddlewaretoken': csrf,
            'email': email,
            'make-primary-email-form-submit': '',
        }

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        defaultMsg = [f"Confirmation e-mail sent to {email}", "Failed to send confirmation e-mail"]

        ob = OriginalBool(True, defaultMsg)

        res = self.session.post('https://holara.ai/accounts/profile/', data=data)

        self._getError(ob, defaultMsg, res)

        return ob

    def GetHoloGems(self) -> OriginalBool:
        self._permission()
        res = self.session.get("https://holara.ai/accounts/profile/")

        defaultMsg = ["Holo Gems", "Unexpected Errors"]

        ob = OriginalBool(True, defaultMsg)

        if res.status_code == 200:
            html = BeautifulSoup(res.text, "html.parser")
            hologemCount = html.find("span", class_="hologems").text.split(" ")[0]
            defaultMsg[0] = {"hologemCount": int(hologemCount)}
            ob.setMessage(defaultMsg)
        else:
            self._getError(ob, defaultMsg, res)

        return ob

    def GetReferences(self) -> OriginalBool:
        res = self.session.get("https://holara.ai/holara/api/1.0/get_feed_images")

        defaultMsg = [{}, f"Unable to get references(status: {res.status_code})"]

        ob = OriginalBool(True, defaultMsg)

        if res.status_code != 200:
            defaultMsg[0] = res.json()
            ob.setMessage(defaultMsg)
        else:
            ob.setMessage(defaultMsg)
            ob.setBool(False)


        return ob

    # ======================================================================
    # ======================================================================
    # ======================================================================
    def Plans(self) -> OriginalBool:
        res = self.session.get("https://holara.ai/pricing/")

        defaultMsg = [{}, f"Unable to get references(status: {res.status_code})"]

        ob = OriginalBool(True, defaultMsg)

        if res.status_code == 200:
            html = BeautifulSoup(res.text, "html.parser")
            planHolder = html.find("div", class_="card-deck mb-3 text-center")
            plans = {}
            for elem in planHolder:
                planName  = elem.find("div", class_="card-header").find("strong").text
                price = elem.find("h1", class_="pricing-card-title")
                features = []
                for section in elem.find_all("li", class_="pricing-section"):
                    text = ""
                    for e in section.find_all():
                        if e.text: text += e.text
                    features.append(text)

                plans[planName] = {
                    "price": price,
                    "features": features
                }

            defaultMsg[0] = res.json()
            ob.setMessage(defaultMsg)
        else:
            ob.setMessage(defaultMsg)
            ob.setBool(False)

        return ob

    def addFavorites(self, imageUUID:str) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/holara/")
        data = {
            'image_uuid': imageUUID,
            'csrfmiddlewaretoken': csrf,
        }

        res = self.session.post('https://holara.ai/holara/api/1.0/favorite_image', data=data)

        defaultMsg = ["Prompt favorited!", "failed to add favorites"]
        ob = OriginalBool(True, defaultMsg)

        if res.status_code != 200:
            defaultMsg[1] = res.text
            ob.setMessage(False)

        return ob

    def getFavorite(self):
        self._permission()

        res = self.session.get('https://holara.ai/holara/api/1.0/get_favorite_prompts')

        defaultMsg = [{}, "failed to get favorites"]
        ob = OriginalBool(True, defaultMsg)

        if res.status_code == 200:
            defaultMsg[0] = res.json()
            ob.setMessage(defaultMsg)
        else:
            defaultMsg[1] = res.text
            ob.setMessage(False)

        return ob

    def removeFavorites(self, favId:int) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/holara/")
        data = {
            'favorite_id': str(favId),
            'csrfmiddlewaretoken': csrf
        }

        res = self.session.post('https://holara.ai/holara/api/1.0/delete_favorite_prompt', data=data)
        defaultMsg = ["Prompt removed!", "failed to remove favorites"]
        ob = OriginalBool(True, defaultMsg)

        if res.status_code != 200:
            defaultMsg[1] = res.text
            ob.setBool(False)

        return ob

    def redeemGift(self, code:str) -> OriginalBool:
        self._permission()
        csrf = self.csrf("https://holara.ai/holara/")
        data = {
            'code': code,
            'csrfmiddlewaretoken': csrf,
        }

        res = self.session.post('https://holara.ai/holara/api/1.0/redeem_gift_code', data=data)

        defaultMsg = ["Gift redeemed!", "failed to redeem gift"]
        ob = OriginalBool(True, defaultMsg)

        if res.status_code != 200:
            defaultMsg[1] = res.text
            ob.setBool(False)

        return ob

    def randomPrompt(self, seed:int=random.random()):
        if type(seed) == float:
            if "sessionid" not in self.session.cookies:
                seed = int(random.random() * 1000)
            else:
                seed = int(random.random() * 2 ** 31 - 1)

        res = self.session.get(f'https://holara.ai/holara/api/1.0/random_prompt?seed={seed}')

        defaultMsg = ["Gift redeemed!", "failed to redeem gift"]
        ob = OriginalBool(True, defaultMsg)

        if res.status_code == 200:
            defaultMsg[0] = res.json()
            ob.setMessage(defaultMsg)
        else:
            ob.setBool(False)

        return ob

    def generate(self, prompt:str, model:str, steps:int=28, scale:int=12, strength:int=60,  size:tuple=(512, 512), isRandom:bool=True, seed:int=int(random.random() * 2 **32)):
        self._permission()
        csrf = self.csrf("https://holara.ai/holara/")

        defaultMsg = [{}, "failed to generate image"]
        ob = OriginalBool(True, defaultMsg)

        if size[0] not in [512, 768, 1152] or size[1] not in [512, 768, 1152]:
            raise Exception("Invalid size (512, 768, 1152) only")

        validModels = self.getModels()
        if validModels:
            models = validModels.v
            if model not in models:
                raise Exception("Invalid model name")
        else:
            raise Exception(validModels.v)

        if steps < 10 or steps > 30:
            raise Exception("Steps must be between 10 and 30")

        if strength < 0 or strength > 100:
            raise Exception("Strength must be between 0 and 100")

        if scale < 0 or scale > 100:
            raise Exception("Scale must be between 0 and 100")

        data = {
            "prompt": prompt,
            "negative_prompt": "",
            "model": model,
            "width": size[0],
            "height": size[1],
            "steps": steps,
            "cfg_scale": scale,
            "strength": strength,
            "seed": seed,
            "history": True,
            "random_autogen": True,
            "variations_autogen": True,
            "quality_tags": True,
            "num_images": 1,
            "random_prompt_seed": int(random.random() * 2 **32),
            "init_image": "",
            "skip": 1,
            "continuous_mode": "off",
            "csrfmiddlewaretoken": csrf
        }

        res = self.session.post('https://holara.ai/holara/api/1.0/generate_image', data=data)
        if res.status_code != 200:
            ob.setBool(False)
        else:
            defaultMsg[0] = res.json()
            ob.setMessage(defaultMsg)

        return ob

    def getModels(self):
        res = self.session.get("https://holara.ai/holara/")

        defaultMsg = [[], "failed to get models"]
        ob = OriginalBool(True, defaultMsg)

        if res.status_code == 200:
            html = BeautifulSoup(res.text, "html.parser")
            models = []
            for elem in html.find_all("div", class_="model-selection text-center"):
                ModelName = str(elem).split("setModel('")[1].split("'")[0]
                models.append(ModelName)
            defaultMsg[0] = models
        else:
            ob.setBool(False)
            defaultMsg[1] = f"Unexpected Errors (status={res.status_code})"
            ob.setMessage(defaultMsg)

        return ob
