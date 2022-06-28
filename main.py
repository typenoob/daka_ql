import traceback
from requests import Session
from Crypto.Cipher import DES
from Crypto.Util import Padding
from base64 import b64encode, b64decode
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
        code = parse.parse_qs(parse.urlparse(self.__session.get(
            'http://fangyi.zstu.edu.cn:4500/connect/authorize?client_id=INTERNAL00000000CODE&redirect_uri=http%3A%2F%2Ffangyi.zstu.edu.cn%3A6006%2Foidc-callback&response_type=code&scope=email%20profile%20roles%20openid%20iduo.api&state=962c0c72141c4ef590c2ea47e546b7cb&code_challenge=KzJbQxDXdR2yk-yFWGfUrhGXf83VTYMzAOL6YvNmGdE&code_challenge_method=S256&acr_values=idp%3APlatform&response_mode=query').url).query)['code']
        payload =\
            {
                'client_id': 'INTERNAL00000000CODE',
                'client_secret': 'INTERNAL-b5d5-7eba-1d182998574a',
                'code': code,
                'redirect_uri': 'http://fangyi.zstu.edu.cn:6006/oidc-callback',
                'code_verifier': '3e5fdab5c6d54b81a8e20d7356b5b6b1248a9dbf058d41169afc7670da5202f6a878be5cd6f1482f832c93bd7227c90f',
                'grant_type': 'authorization_code'
            }
        res = self.__session.post(
            'http://fangyi.zstu.edu.cn:4500/connect/token', payload)
        self.__session.headers = {
            'Authorization': 'Bearer {}'.format(json.loads(res.text)['access_token'])}

    def submit(self):
        url = 'http://fangyi.zstu.edu.cn:8008/form/api/FormHandler/SubmitBusinessForm'
        payload = {"biz": {"GUID": "092132701CCDE43C2C9340FFD", "CURRENTLOCATION": "浙江省 宁波市 慈溪市", "CURRENTSITUATION": "低风险地区", "ARRIVESTATUS": "在（入）校", "TEMPERATURESITUATION": "正常", "TEMPERATURE": "", "HEALTHCODESTATUS": "绿码", "VACCINATIONSTATUS": "已完成首轮全部针剂", "ZHJZSJ": "2021-09-22 00:00:00", "WJZYY": None, "JTYY": None, "XGYMZL": "科兴灭活疫苗", "CONFIRMEDSTATE": "无", "CONFIRMEDDATETIME": None, "CONFIRMEDQUARANTINEDATETIME": None, "CONFIRMEDRELIEVEDATETIME": None, "QUARANTINESTATUS": "未隔离", "NOTIFICATIONMODE": "", "QUARANTINEREASON": "", "QUARANTINETYPE": "", "QUARANTINELOCATION": "", "QUARANTINESTARTTIME": "", "ESTIMATEQUARANTINEENDTIME": "", "PROCESSES": "", "LIVINGHISTORYSTATUS": "无", "LIVINGHISTORYSTATUS1": "",
                           "LIVINGHISTORYLOCATION": "", "TZRY": "否", "TZRYSM": None, "SFYHSYXBG": "未检测", "KYJCJG": "未检测", "DQXXZT": "在校学习（含科研）", "DQSZDWMC": None, "TJ_QRNR": "上述内容客观如实填写，填写人对本表真实性负责，如瞒报、虚报产生不良后果，承担相应责任。", "DKLX": "本人打卡", "CLR": "陈裕涛", "CLSJ": None, "ZHXGR": None, "XGNR": "30.21830940246582,121.31095123291016", "ZHXGSJ": None}, "task": {}, "sign": {}, "user": {"userId": "ZSTU/2019329600124", "userName": "陈裕涛", "domain": "ZSTU"}, "conf": {"bizId": "092132701CCDE43C2C9340FFD", "platform": "Weixin", "IsDraft": False, "IsDeleteDraft": False}, "form": {"formId": "1817056F47E744D3B8488B", "formName": "疫情填报（学生）"}, "approvalBtn": {"code": "Submit", "visible": True, "title": "提交", "size": "medium", "type": "primary"}}
        payload['biz'] = self.__arrange_data()
        res = self.__session.post(url, json.dumps(payload), headers={
                                  'Content-type': 'application/json'})
        print(res.content.decode('utf-8'))
        self.__message = res.content.decode('utf-8')

    def __arrange_data(self):
        url = f'http://fangyi.zstu.edu.cn:8008/form/api/DataSource/GetDataSourceByNo?sqlNo={env.get("sqlNo")}'
        res = json.loads(self.__session.get(url).text)
        res['data'][0]['CURRENTDATE'] = str(datetime.datetime.strptime(
            res['data'][0]['CURRENTDATE'], '%Y-%m-%d %H:%M:%S')+datetime.timedelta(days=1))
        res['data'][0]['CURRENTTIME'] = str(datetime.datetime.strptime(
            res['data'][0]['CURRENTTIME'], '%Y-%m-%d %H:%M:%S')+datetime.timedelta(days=1))
        return(res['data'][0])

    def get_session(self):
        return self.__session

    def get_message(self):
        return self.__message

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
    try:
        stu = ZstuSso(env.get('sno'), env.get('password'))
        stu.login()
        stu.set_token()
        stu.submit()
        load_send()
        if send:
            send("任务执行结果：", f"\n{stu.get_message}")
    except:
        logger.info('❌没有设置环境变量')


env = os.environ
if __name__ == '__main__':
    main()
