import hashlib
import traceback
import random
import math
import time
from requests import Session
from Crypto.Cipher import DES
from Crypto.Util import Padding
from base64 import b64encode, b64decode, urlsafe_b64encode
from re import compile
from urllib import parse
import json
import datetime
import logging
import os
import sys
logger = logging.getLogger(name=None)  # 创建一个日志对象
logging.Formatter("%(message)s")  # 日志内容格式化
logger.setLevel(logging.INFO)  # 设置日志等级
logger.addHandler(logging.StreamHandler())  # 添加控制台日志
# logger.addHandler(logging.FileHandler(filename="text.log", mode="w"))  # 添加文件日志


def load_send() -> None:
    logger.info("加载推送功能中...")
    global send
    send = None
    cur_path = os.path.abspath(os.path.dirname(__file__))
    sys.path.append(cur_path)
    if os.path.exists(cur_path + "/notify.py"):
        try:
            from notify import send
        except Exception:
            send = None
            logger.info(f"❌加载通知服务失败!!!\n{traceback.format_exc()}")


def base64UrlEncode(data):
    return urlsafe_b64encode(data).rstrip(b'=')


def generateRandomString(length):
    text = ""
    possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(length):
        text += possible[math.floor(random.random() * len(possible))]
    return text


def generateCodeChallenge(code_verifier):
    return base64UrlEncode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8')


class ZstuSso:
    def __init__(self, username: str, password: str) -> None:
        if username == None or password == None:
            raise RuntimeError
        self.__username = username
        self.__password = password
        self.__session = Session()

    def login(self) -> Session:
        login_url = 'https://sso.zstu.edu.cn/login'
        res = self.__session.get(login_url).text
        execution, croypto = self.__get_execution_and_crypto(res)
        payload = \
            {
                'username': self.__username,
                'type': 'UsernamePassword',
                '_eventId': 'submit',
                'geolocation': '',
                'execution': execution,
                'captcha_code': '',
                'croypto': croypto,
                'password': self.__encrypto_password(croypto),
            }
        res = self.__session.post(login_url, payload)

    def set_token(self):
        code_verifier = generateRandomString(96)
        code_challenge = generateCodeChallenge(code_verifier)
        url = f'http://fangyi.zstu.edu.cn:4500/connect/authorize?client_id=INTERNAL00000000CODE&redirect_uri=http%3A%2F%2Ffangyi.zstu.edu.cn%3A6006%2Foidc-callback&response_type=code&scope=email%20profile%20roles%20openid%20iduo.api&state=962c0c72141c4ef590c2ea47e546b7cb&code_challenge={code_challenge}&code_challenge_method=S256&acr_values=idp%3APlatform&response_mode=query'
        code = parse.parse_qs(parse.urlparse(
            self.__session.get(url).url).query)['code']
        payload =\
            {
                'client_id': 'INTERNAL00000000CODE',
                'client_secret': 'INTERNAL-b5d5-7eba-1d182998574a',
                'code': code,
                'redirect_uri': 'http://fangyi.zstu.edu.cn:6006/oidc-callback',
                'code_verifier': code_verifier,
                'grant_type': 'authorization_code'
            }
        res = self.__session.post(
            'http://fangyi.zstu.edu.cn:4500/connect/token', payload)
        self.__session.headers = {
            'Authorization': 'Bearer {}'.format(json.loads(res.text)['access_token'])}

    def submit(self):
        url = 'http://fangyi.zstu.edu.cn:8008/form/api/FormHandler/SubmitBusinessForm'
        payload = {"task": {}, "sign": {}, "conf": {"bizId": "", "platform": "Weixin", "IsDraft": False, "IsDeleteDraft": False}, "form": {
            "formId": "1817056F47E744D3B8488B", "formName": "疫情填报（学生）"}, "approvalBtn": {"code": "Submit", "visible": True, "title": "提交", "size": "medium", "type": "primary"}}
        payload['biz'] = self.__arrange_data()
        payload['user'] = {"userId": f"ZSTU/{self.__username}",
                           "userName": f"{payload['biz']['NAME']}", "domain": "ZSTU"}
        logger.info(payload['biz'])
        res = self.__session.post(url, json.dumps(payload), headers={
                                  'Content-type': 'application/json'})
        self.__message = res.content.decode('utf-8')

    def __arrange_data(self):
        url = f'http://fangyi.zstu.edu.cn:8008/form/api/DataSource/GetDataSourceByNo?sqlNo={b64encode(f"ZJDK_XS${self.__username}".encode("utf-8")).decode("utf-8")}'
        res = json.loads(self.__session.get(url).text)
        # res['data'][0]['CURRENTDATE'] = str(datetime.datetime.strptime(
        #     res['data'][0]['CURRENTDATE'], '%Y-%m-%d %H:%M:%S')+datetime.timedelta(days=1))
        res['data'][0]['CURRENTTIME'] = datetime.datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S')
        res['data'][0]['CURRENTDATE'] = datetime.datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S')
        return(res['data'][0])

    def get_session(self):
        return self.__session

    def get_message(self):
        return self.__message

    def static_check(self):
        url = 'http://fangyi.zstu.edu.cn:8008/form/api/FormHandler/GetFormInfo?formId=1817056F47E744D3B8488B&bizId='
        res = json.loads(self.__session.post(
            url, headers={
                'Content-type': 'application/json'}).text)
        result = res['data']['formConfiguration'] == json.load(
            open("memory.txt", "r"))
        json.dump(res['data']['formConfiguration'], open("memory.txt", "w"))
        return result

    def check(self) -> bool:
        url = f'http://fangyi.zstu.edu.cn:8008/form/api/DataSource/GetDataSourceByNo?sqlNo={b64encode(f"JTDK_XS${self.__username}".encode("utf-8")).decode("utf-8")}'
        res = json.loads(self.__session.get(url).text)
        logger.info('Checking data:{}'.format(res))
        if len(res['data']) == 0:
            return False
        unix_dtime = int(time.mktime(datetime.date.today().timetuple()))
        unix_ctime = int(time.mktime(time.strptime(
            res['data'][0]['CURRENTDATE'], '%Y-%m-%d %H:%M:%S')))
        logger.info('unix_dtime: {}, unix_ctime:{}'.format(
            unix_dtime, unix_ctime))
        return True if unix_dtime <= unix_ctime else False

    def __get_execution_and_crypto(self, data: str):
        execution_pat = compile('<p id="login-page-flowkey">(.*?)</p>')
        crypto_pat = compile('<p id="login-croypto">(.*?)</p>')
        return execution_pat.search(data).group(1), crypto_pat.search(data).group(1)

    def __encrypto_password(self, key: str) -> str:
        key = b64decode(key)
        enc = DES.new(key, DES.MODE_ECB)
        data = Padding.pad(self.__password.encode('utf-8'), 16)
        return b64encode(enc.encrypt(data))


def main():
    #os.environ['zstu']="sno=xxxx;password=xxxx;"
    zstu = os.environ.get('zstu').split(';')
    list = [{zstu[i].split('=')[0]: zstu[i].split('=')[1], zstu[i+1].split('=')[0]: zstu[i+1].split('=')[1]}
            for i in range(0, len(zstu)-1, 2)]
    load_send()
    for pair in list:
        try:
            logger.info(f"打卡账号：{pair}")
            stu = ZstuSso(pair['sno'], pair['password'])
            stu.login()
            stu.set_token()
            if (stu.check()):
                if send:
                    send(f"任务执行结果({pair['sno']}):", "\n已经打过卡了")
            elif stu.static_check():
                stu.submit()
                if send:
                    send(f"任务执行结果({pair['sno']}):", f"\n{stu.get_message()}")
            else:
                if send:
                    send("任务执行失败：", "\n静态检查出错")
                break
        except Exception as e:
            logger.info(e)
            logger.info('❌任务运行失败，请检查环境变量是否设置正确')


if __name__ == '__main__':
    main()
