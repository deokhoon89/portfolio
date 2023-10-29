from unittest import result
from PIL import Image
from web3 import Web3
import pyotp
import pymysql
import datetime
import os, sys
import qrcode
import base64
from io import BytesIO
import random
import boto3
import io
from datetime import datetime, timedelta
import gspread
import time
import ssl
import certifi
from slack_sdk import WebClient
from jira import JIRA
from slack_sdk.errors import SlackApiError
import time
import subprocess
import decimal
import requests
from multiprocessing import Pool
import json
import math
from bson.objectid import ObjectId
import zipfile
import pytz
from fastapi import HTTPException
import re

sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from api import ks_api, ex_api, ex_api_v2, dex_api, new_groundchain_api, flux_api, br_api
from kstadium import setting
import platform
import pymongo

env = 'stg'

ex_api_v2.set_env(env)
ks_api.set_env(env)
ex_api.set_env(env)
br_api.set_env(env)
flux_api.set_env(env)
new_groundchain_api.set_env(env)

# DB 접속 준비
kstadium_rest_api = ''
myid = ''
mypasswd = ''

# PRD DB
# PRD
kstadium_rest_api_prd = ''
myid_prd = ''
mypasswd_prd = ''

bridge_stg_db = ''
bridge_stg_myid = ''
bridge_stg_mypasswd = ''

bridge_prd_db = ''
bridge_prd_myid = ''
bridge_prd_mypasswd = ''

# ethscan api key & prd wallet info
eterscan_api_key = ""
mainnet_prd_wallet = "" # PRD QA팀 Wallet
address = "" # 계정


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return str(o)
        return super().default(o)

def mongo_env(env):
    # MongDB 
    # Define base URIs and paths for each environment
    env_data = {
        'dev': {
            'uri': '',
            'tlsCAFile': {
                'Windows': 'D%3A%5Cautotest%5Cswagger%5Cmongo%5Cmongo-prod.pem',
                'Darwin': '%2FUsers%2Fmedium%2Fautotest%2Fswagger%2Fmongo%2Fmongo-prod.pem',
                'Linux' : '%2Fhome%2Fmedium%2Fautotest%2Fswagger%2Fmongo%2Fmongo-prod.pem'
            }
        },
        'stg': {
            'uri': '',
            'tlsCAFile': {
                'Windows': 'D%3A%5Cautotest%5Cswagger%5Cmongo%5Cmongo-prod.pem',
                'Darwin': '%2FUsers%2Fmedium%2Fautotest%2Fswagger%2Fmongo%2Fmongo-prod.pem',
                'Linux' : '%2Fhome%2Fmedium%2Fautotest%2Fswagger%2Fmongo%2Fmongo-prod.pem'
            }
        },
        'prd': {
            'uri': '',
            'tlsCAFile': {
                'Windows': 'D%3A%5Cautotest%5Cswagger%5Cmongo%5Cmongo-prod.pem',
                'Darwin': '%2FUsers%2Fmedium%2Fautotest%2Fswagger%2Fmongo%2Fmongo-prod.pem',
                'Linux' : '%2Fhome%2Fmedium%2Fautotest%2Fswagger%2Fmongo%2Fmongo-prod.pem'
            }
        }
    }

    sysOS = platform.system()

    # Check if environment and OS are valid
    if env not in env_data:
        print(f"Unknown environment: {env}")
    elif sysOS not in env_data[env]['tlsCAFile']:
        print(f"Unsupported operating system: {sysOS}")
    else:
        base_uri = env_data[env]['uri']
        tlsCAFile = env_data[env]['tlsCAFile'][sysOS]
        uri = f"{base_uri}&tlsCAFile={tlsCAFile}"
        
        return uri


# Admin
admin_id = ''
admin_pw = ''

# 공용 패스워드
pw = ''
qapw = ''

#slack jira intergration
slack_token = ""
channel = ''
channelId = ""
jira_server = ""
api_token = ""
auth_JIRA = ("wayne.park@crypted.co.kr",api_token)

def contract_address(env):
    # 변수
    if env == 'stg':
        orgsmgr = ''
        flux_controller = ''
    elif env == 'prd':
        orgsmgr = ''
        flux_controller = ''

    return orgsmgr,flux_controller

eth = 1000000000000000000

######################################
#            A C C O U N T           #
######################################
# STG DB에서 사용자 확인
def check_user_account(user_id,env='stg',qadb=None):
    db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
    if env == 'stg': 
        sql_addr = "SELECT ACCOUNT from kstadium_web_db.TB_CH_MEMBER where USER_ID  ='{}';".format(user_id)
    elif env == 'prd':
        sql_addr = "SELECT ACCOUNT from qa_stg.otp_storage_prd where user_id  ='{}';".format(user_id)
    cursor = db.cursor(pymysql.cursors.DictCursor)
    result={}

    # STG DB에서 사용자 계정 우선 확인
    try:
        cursor.execute(sql_addr)
        user_addr = cursor.fetchall()[0]['ACCOUNT']
        print(user_addr)
    except IndexError: # 사용자 ID가 없을 경우
        print('[{}] ID가 존재 하지 않습니다.'.format(env))
        result['result'] = False
        result['resultMessage'] = '{} DB에 사용자가 존재하지 않습니다.'.format(env)
        db.close()
        return result
    
    # QA DB에서 사용자 계정 확인
    if qadb != None:
        qadb_addr = "SELECT user_id, secret_key from qa_stg.otp_storage where user_id  ='{}';".format(user_id)
        try:
            cursor.execute(qadb_addr)
            db_result = cursor.fetchall()[0]
            user_addr = db_result['user_id']
            result['secretkey'] = db_result['secret_key']
            print(user_addr,result['secretkey'])
        except IndexError: # 사용자 ID가 없을 경우
            print('[QA DB] ID가 존재 하지 않습니다.')
            result['result'] = False
            result['resultMessage'] = 'QA DB에 사용자가 존재하지 않습니다.'
            db.close()
            return result

    result['result'] = True
    result['address'] = user_addr
    result['resultMessage'] = 'Success'
    db.close()
    return result

# QA DB에서 사용자 확인
def check_user_secretkey(user_id,user_addr,env):
    db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
    cursor = db.cursor(pymysql.cursors.DictCursor)
    result={}
    if env =='stg':
        sql = "SELECT secret_key from qa_stg.otp_storage WHERE user_id = '{}';".format(user_id)
    elif env == 'prd':
        sql = "SELECT secret_key from qa_stg.otp_storage_prd WHERE user_id = '{}';".format(user_id)

    # QA DB에서 Sccret키를 못 가져올 경우 사용자가 없는 것으로 판단 
    try:
        cursor.execute(sql)
        otp_secretkey = cursor.fetchall()[0]['secret_key']
        print(user_addr)
        result['result'] = True
        result['address'] = user_addr
        result['secretkey'] = otp_secretkey
        result['resultMessage'] = 'Success'
    # 사용자 ID가 없을 경우
    except IndexError: # OTP 코드 요청일 경우 
        print('[STG] ID를 다시 확인해 주세요')
        result['result'] = False
        result['resultMessage'] = 'QA DB에 사용자가 존재하지 않습니다.'
    db.close()
    return result


def create_user(user_id,password,env='stg'):
    result={}

    emailaddr = user_id+"@yopmail.com"
    code_ = ks_api.get_make_email_authcodeV2("join",emailaddr,name=user_id,userid=user_id)    
    if code_["statusCode"] == 200:
        code = ks_api.get_email_authcode(emailaddr)
    else:
        result['result'] = False
        result['resultMessage'] = 'Email 인증 코드 발송 실패'
        return result        
    if code["statusCode"] == 200:        
        auth = ks_api.post_email_authcode(emailaddr, code["authCode"])
    else:
        result['result'] = False
        result['resultMessage'] = 'Email 인증 코드 획득 실패'
        return result   
    if auth["statusCode"] == 200:        
        join = ks_api.post_join(emailaddr, code["authCode"], user_id, password)
    else:
        result['result'] = False
        result['resultMessage'] = 'Email 인증 코드 미일치'
        return result   
    if join["statusCode"] == 200:    
        ks_api.set_env(env)
        secretKey = get_otp(user_id, password, env)
    else:
        result['result'] = False
        result['resultMessage'] = '신규 가입 실패'
        return result   
    if secretKey[2] == 200:
        post_sqe_db_id(secretKey,env)
    else:
        result['result'] = False
        result['resultMessage'] = 'OTP 오류'
        return result  
    print(user_id, password, secretKey[1])
    result['result'] = True
    result['user_id'] = user_id
    result['resultMessage'] = '사용자 계정 생성 완료'
    return result  

# STG DB에서 사용자 member_id 확인
def check_user_memberid(user_id,env,qadb=None):
    db = setting.db_connect(env, 'ks_app')
    sql_addr = "SELECT id FROM kstadium_main.`member` where user_id = '{}';".format(user_id)
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute(sql_addr)
    member_id = cursor.fetchall()[0]['id']
    print(member_id)
    
def check_user_userid(address,env,qadb=None):
    db = setting.db_connect(env, 'ks_app')
    sql_addr = "SELECT user_id FROM kstadium_main.`member` where address = '{}';".format(address)
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute(sql_addr)
    user_id = cursor.fetchall()[0]['user_id']
    return user_id

def check_user_address(user_id,env,qadb=None):
    db = setting.db_connect(env, 'ks_app')
    sql_addr = "SELECT address FROM kstadium_main.`member` where user_id = '{}';".format(user_id)
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute(sql_addr)
    address = cursor.fetchall()[0]['address']
    return address

# Admin 로그인 후 Access token 리턴
def get_admin_accesstoken(user_id='superadmin',password='1q2w3e4r!',env='stg'):
    ks_api.set_env(env)
    result = {}
    result_admin = ks_api.post_admin_login(user_id,password)

    if result_admin['statusCode'] == 200:
        result['result'] = True
        result['resultMessage'] = result_admin['resultMessage']
        result['accessToken'] = result_admin['accessToken']
        result['refreshToken'] = result_admin['refreshToken']
    else:
        result['result'] = False
        result['resultMessage'] = result_admin['resultMessage']
    return result


######################################
#               O T P                #
######################################
# STG DB에 OTP Secretkey 갱신
def update_secretkey(user_id,user_pw):
    # STG DB에 사용자가 있는지 확인 후, 기존 OTP 코드를 가져온다.
    result = check_user_account(user_id, 'stg', 'qa_db')
    this_result = {}

    if result['result']:
        this_result['result'] = True
        this_result['userID'] = user_id
        this_result['secretkey'] = result['secretkey']
        db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
        cursor = db.cursor(pymysql.cursors.DictCursor)
        sql_update = "UPDATE qa_stg.otp_storage SET secret_key = '{}', update_date = NOW() WHERE user_id = '{}';"

        # Admin 계정 로그인
        admin_token = ks_api.post_admin_login(admin_id,admin_pw)

        # OTP Reset, 새로운 OTP Secret 키 생성 후 OTP code 확인
        print('OTP Reset')
        ks_api.post_otp_reset(user_id,admin_token['accessToken'])
        token = ks_api.post_login(user_id,user_pw)
        ks_api.post_otp_secretkey(token['accessToken'])
        otp_secretkey_new = ks_api.post_otp_secretkey(token['accessToken'],True,True)['encodedKey']

        print('New OTP Secret KEY :',otp_secretkey_new)
        totp = pyotp.TOTP(otp_secretkey_new)
        otpcode = totp.now()

        print('OTP Code 확인')
        ks_api.post_otp_verify(token['accessToken'],otpcode)
        this_result['new_secretkey'] = otp_secretkey_new

        # 갱신 후 DB 업데이트는 공용으로 처리 - OTP Secret key DB updqte
        print('OTP Secret DB update') 
        print(sql_update.format(otp_secretkey_new,user_id))
        cursor.execute(sql_update.format(otp_secretkey_new,user_id))
        db.commit() # DB update시 필요 
        db.close()
    else:
        this_result['result'] = False
        this_result['userID'] = user_id
        this_result['resultMessage'] = result['resultMessage']
    return this_result


def get_qrcode(user_id, otp_secretkey):
    # STG DB에 사용자가 있는지 확인 후, 기존 OTP 코드를 가져온다.
    result = check_user_account(user_id)
    this_result = {}

    # s3 연동
    s3 = boto3.client('s3')
    bucket_name = 'work-qa'       

    if result['result']:
        this_result['result'] = result['result']
        totp_uri = pyotp.totp.TOTP(otp_secretkey).provisioning_uri(name=user_id+'@yopmail.com', issuer_name=user_id)        
        img = qrcode.make(totp_uri)
   
        if "LAMBDA_RUNTIME_DIR" in os.environ:
            # 이미지파일을 이진 파일로 변경
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_bytes.seek(0)

            # s3 버킷 정의
            bucket_name = 'work-qa'
            object_key = 'qr-code.png'
            metadata = {
                'Content-Type': 'image/png',
            }
            
            # 정의된 s3 버킷에 추가
            s3.put_object(Bucket=bucket_name, Key=object_key, Body=img_bytes.getvalue(), Metadata=metadata)        

            # s3 버킷에 추가된 png 파일 추출
            response = s3.get_object(Bucket=bucket_name, Key="qr-code.png")
            content = response['Body'].read()  
        else: # Local static에서 처리
            img = qrcode.make(totp_uri)
            print('img',img)
            # Method 1
            print(os.getcwd())
            # img.save(os.path.join(os.getcwd()+'/static', 'qr_code.png'))
            # print(os.getcwd())
            # img.save(os.path.join(os.getcwd()+'/static/', 'qr_code.png'))
            img.save('./static/qr_code.png')
            print('img.save OK')
            with open("./static/qr_code.png", "rb") as image_file:
                content = base64.b64encode(image_file.read()).decode('utf-8')

        this_result['img'] = content
        this_result['result'] = '200'
        this_result['secretkey'] = otp_secretkey
    else:
        this_result['result'] = result['result']
        this_result['message'] = result['message']

    return this_result

# OTP code를 가져온다
def get_otpcode(otp_secretkey,user_id,password,env):
    result = {}
    ks_api.set_env(env)
    totp = pyotp.TOTP(otp_secretkey)
    time_remaining = totp.interval - datetime.now().timestamp() % totp.interval

    otpcode = totp.now()
    remaining = '{0:.2f} 초'.format(time_remaining)
    print('OTP Code : {0}  남은 시간 : {1:.2f} 초'.format(otpcode, time_remaining))
    result['otpcode'] = otpcode
    result['remaining'] = remaining
    result['secretkey'] = otp_secretkey
    if env == 'stg':
        token = ks_api.post_otp_login(user_id, password, env ,False, False)
        result['KS accessToken'] = token.get('accessToken')
    return result

# 신규 유저 확인
def check_new_user(user_id, env='stg'):
    db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
    cursor = db.cursor(pymysql.cursors.DictCursor)
    result={}
    try:
        if env == "stg":
            sql="SELECT user_id FROM qa_stg.otp_storage WHERE user_id = '{}';".format(user_id)
            cursor.execute(sql)
            result = cursor.fetchall()[0]['user_id']
        elif env == "prd":
            sql="SELECT user_id FROM qa_stg.otp_storage_prd WHERE user_id = '{}';".format(user_id)
            cursor.execute(sql)
            result = cursor.fetchall()[0]['user_id']
        else:
            result = "env_error"
    except(IndexError):
        result = "new_user"

    return result

# user 추가(STG Only)
def post_sqe_db_id(value_, env='stg'):    
    db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
    cursor = db.cursor(pymysql.cursors.DictCursor)
    if env == "stg":
        sql = "INSERT INTO qa_stg.otp_storage (user_id, update_date, secret_key) VALUES ('{}', now(), '{}');"
    elif env == "prd":
        sql = "INSERT INTO qa_stg.otp_storage_prd (user_id, update_date, secret_key) VALUES (%s, now(), %s);"  
    print(value_) 
    print(value_[0][0])
    print(value_[0][1])
    cursor.execute(sql.format(value_[0],value_[1]))
    db.commit()
    db.close()

# otp 가져오기
def get_otp(id, pw, env='stg'):    
    token = ks_api.post_login(id, pw)    
    if token["statusCode"] != 200:
        return [id, "login_failed", token["statusCode"]]   
        
    else:        
        #prd의 경우, otp 초기화 권한이 없어 운영팀에 문의 필요.
        if env == "stg":
            print('Token=',token["isOtpSettingUser"])
            if token["isOtpSettingUser"] == "true":
                admin_token = ks_api.post_admin_login(admin_id,admin_pw)
                reset = ks_api.post_otp_reset(id, admin_token["accessToken"])
                token = ks_api.post_login(id, pw)  
        #otp_secretkey 추출
        otp_secretkey = ks_api.post_otp_secretkey(token["accessToken"])        
        if otp_secretkey["statusCode"] != 200:
            return [id, "secretKey_failed", otp_secretkey["statusCode"]]      
        else:
            # generating TOTP codes with provided secret
            totp = pyotp.TOTP(otp_secretkey['encodedKey'])
            otpcode = totp.now()        

            two_authentication = ks_api.post_otp_verify(token["accessToken"],otpcode)        

            return [id, otp_secretkey['encodedKey'], two_authentication["statusCode"]]

# 신규유저 추가 / Secret Key 생성
def add_new_user(user_id, password, env='stg'):
    result = {}
    data = {}
    check_user = check_new_user(user_id, env)
    if check_user == "env_error":
        result["resultCode"] = "Failed"
        result["resultMessage"] = "Environment error"
        result["data"] = "null"
    elif check_user == user_id:
        result["resultCode"] = "Failed"
        result["resultMessage"] = "A user account already exists in the QA DB."        
        result["data"] = "null"
    elif check_user == "new_user":       
        ks_api.set_env(env) 
        secretKey = get_otp(user_id, password, env)            
        if secretKey[2] == 200:
            post_sqe_db_id(secretKey,env)            
            result["resultCode"] = "Success"
            result["resultMessage"] = "New user creation complete"            
            data["user_id"] = secretKey[0]
            data["secret_key"] = secretKey[1]
            result["data"] = data
        elif secretKey[1] == "login_failed":
            result["resultCode"] = "Failed"                
            result["resultMessage"] = "Please check your login information again" 
            result["data"] = "null"  
        elif secretKey[1] == "secretKey_failed":
            result["resultCode"] = "Failed"
            result["resultMessage"] = "Failed to generate secret key"            
            result["data"] = "null"   

    return result

######################################
#          Launch Pad                #
######################################
# DEX 관련 접속 URL 생성
def launchPad_accesskey(user_id, password, env='stg'):
    this_result = {}
    ks_api.set_env(env)    
    token = ks_api.post_otp_login(user_id, password, env ,False, False)
    result = ks_api.get_external_accessKey(token.get('accessToken'),False,False)
    if env == 'stg':
        this_result['url'] = ''.format(result.get('accessKey'))
    elif env == 'prd':
        this_result['url'] = ''.format(result.get('accessKey'))
    this_result['accessKey'] = result.get('accessKey')
    return this_result


######################################
#               D E X                #
######################################
# DEX 관련 접속 URL 생성
def dex_accesskey(user_id, password, env='stg'):
    this_result = {}
    ks_api.set_env(env)    
    token = ks_api.post_otp_login(user_id, password, env ,False, False)
    result = ks_api.get_external_accessKey(token.get('accessToken'),False,False)
    if env == 'stg':
        this_result['url'] = ''.format(result.get('accessKey'))
    elif env == 'prd':
        this_result['url'] = ''.format(result.get('accessKey'))
    this_result['accessKey'] = result.get('accessKey')
    return this_result

# DEX 관련 접속 URL 생성
def dex_token(accesskey):
    this_result = {}
    # token = ks_api.post_otp_login(user_id, pw, 'stg',False, False)
    result = ks_api.post_dex_login(accesskey,False,False)
    this_result['accessToken'] = result.get('accessToken')
    return this_result

def get_totalsupply_reserve(env):
    if env == "stg":
        totalsupply_url = ''
        reserve_url = ''
    elif env == "prd":    
        totalsupply_url = ''
        reserve_url = ''

    wei = 1000000000000000000

    tokenList = [{"KSTA":"NST"},{"KSTA":"inKSTA"},{"KSTA":"ksUSDT"},{"KSTA":"ksETH"},{"KSTA":"LOUI"},{"LOUI":"ksETH"},{"LOUI":"ksUSDT"},{"NST":"XDC"},{"KSTA":"DLT"}]
    result_total_dic = {}
    result_reserveA_dic = {}
    result_reserveB_dic = {}
    for i in tokenList:        
        key = list(i.keys())[0]
        value = i[key]        
        key_ = key+"-"+value
        
        url = totalsupply_url+f"{key}/{value}"
        response = requests.get(url)
        data = response.json()
        try:
            totalsupply = float(data)
            result = str(decimal.Decimal(totalsupply)/wei)
            result_total_dic[key_] = result
        except(TypeError):
            result = "not in whitelist"
            result_total_dic[key_] = result

        #reserve
        url = reserve_url+f"{key}/{value}".format(i)    
        response = requests.get(url)
        data = response.json()        
        try:        
            reserve_a = float(data['reserveA'])
            reserve_b = float(data['reserveB'])
            
            reserve_a_result = str(decimal.Decimal(reserve_a)/wei)
            reserve_b_result = str(decimal.Decimal(reserve_b)/wei)
            
            result_reserveA_dic[key_] = reserve_a_result
            result_reserveB_dic[key_] = reserve_b_result
            
        except(KeyError):
            result_reserveA_dic[key_] = "not in whitelist"
            result_reserveB_dic[key_] = "not in whitelist"            

    message = "Total Supply & Reserve A, B"

    result = [result_total_dic["KSTA-NST"], result_reserveA_dic["KSTA-NST"], result_reserveB_dic["KSTA-NST"], 
            result_total_dic["KSTA-inKSTA"], result_reserveA_dic["KSTA-inKSTA"], result_reserveB_dic["KSTA-inKSTA"],
            result_total_dic["KSTA-ksUSDT"], result_reserveA_dic["KSTA-ksUSDT"], result_reserveB_dic["KSTA-ksUSDT"],
            result_total_dic["KSTA-ksETH"], result_reserveA_dic["KSTA-ksETH"], result_reserveB_dic["KSTA-ksETH"],
            result_total_dic["KSTA-LOUI"], result_reserveA_dic["KSTA-LOUI"], result_reserveB_dic["KSTA-LOUI"],
            result_total_dic["LOUI-ksUSDT"], result_reserveA_dic["LOUI-ksUSDT"], result_reserveB_dic["LOUI-ksUSDT"],
            result_total_dic["LOUI-ksETH"], result_reserveA_dic["LOUI-ksETH"], result_reserveB_dic["LOUI-ksETH"],
            result_total_dic["NST-XDC"], result_reserveA_dic["NST-XDC"], result_reserveB_dic["NST-XDC"],
            result_total_dic["KSTA-DLT"], result_reserveA_dic["KSTA-DLT"], result_reserveB_dic["KSTA-DLT"]]

    return message, result


#소수점 절삭
def truncate(number, digits) -> float:    
    nbDecimals = len(str(number).split('.')[1])    
    if nbDecimals <= digits:
        return number
    stepper = 10.0 ** digits
    return math.trunc(stepper * number) / stepper

# swap 예상치 구하기
def get_swap_estimate(env, tokenA, tokenB, inputToken, inputAmount):
    ks_api.set_env(env)
    dex_api.set_env(env)
    wei = 10**18
    id = ""
    pw = ""

    login = ks_api.post_otp_login(id,pw, nw=env)
    dex_accessKey = ks_api.get_external_accessKey(login["accessToken"])
    dex_login = ks_api.post_dex_login(dex_accessKey["accessKey"])    
    reserve = dex_api.get_pool_reserve(tokenA, tokenB, d_l1=False, d_l2=False)

    reserveA = float(reserve["reserveA"]) / wei
    reserveB = float(reserve["reserveB"]) / wei

    # 상수 값
    k = reserveA*reserveB    

    # swap fee
    swapFee = inputAmount * 0.0025

    result_dic = {}
    if inputToken == tokenA:
        estimate_reserveA = float(reserveA)+(float(inputAmount)-swapFee)
        estimate_reserveB = float(k)/float(estimate_reserveA)
        estimate_tokenA = inputAmount
        estimate_tokenB = (float(reserveB) - float(estimate_reserveB))
        try:
            estimate_tokenA = truncate(estimate_tokenA, 5)            
        except(IndexError):
            estimate_tokenA = estimate_tokenA
        
        try:
            estimate_tokenB = truncate(estimate_tokenB, 5)            
        except(IndexError):
            estimate_tokenB = estimate_tokenB            

    elif inputToken == tokenB:        
        estimate_reserveB = float(reserveB)+(float(inputAmount)-swapFee)
        estimate_reserveA = float(k)/float(estimate_reserveB)
        estimate_tokenB = inputAmount
        estimate_tokenA = (float(reserveA) - float(estimate_reserveA))

        try:
            estimate_tokenA = truncate(estimate_tokenA, 5)            
        except(IndexError):
            estimate_tokenA = estimate_tokenA
        
        try:
            estimate_tokenB = truncate(estimate_tokenB, 5)            
        except(IndexError):
            estimate_tokenB = estimate_tokenB 

    result_dic[tokenA] = estimate_tokenA
    result_dic[tokenB] = estimate_tokenB

    return result_dic

# Add Liquidity 예상치 구하기

def get_add_liquidity_estimate(env, tokenA, tokenB, inputToken, inputAmount):
    
    ks_api.set_env(env)
    dex_api.set_env(env)    
    id = ""
    pw = ""

    login = ks_api.post_otp_login(id,pw, nw=env)
    dex_accessKey = ks_api.get_external_accessKey(login["accessToken"])
    dex_login = ks_api.post_dex_login(dex_accessKey["accessKey"])    
    reserve = dex_api.get_pool_reserve(tokenA, tokenB)
    totalSupply = float(dex_api.get_reserveTotalSupply(tokenA, tokenB)["totalSupply"])
    reserveA = float(reserve["reserveA"])
    reserveB = float(reserve["reserveB"])

    result_dic = {}
    if inputToken == tokenA:        
        estimate_reserveA = truncate(float(inputAmount), 5)
        estimate_reserveB = truncate(float(((inputAmount)*((reserveB)/(reserveA)))), 5)
        estimate_lpToken = truncate(float(((inputAmount)*(totalSupply)/(reserveA))), 5)

        result_dic[f"{tokenA}-{tokenB}"] = estimate_lpToken
        result_dic[tokenA] = estimate_reserveA
        result_dic[tokenB] = estimate_reserveB

    elif inputToken == tokenB:        
        estimate_reserveB = truncate(float(inputAmount), 5)
        estimate_reserveA = truncate(float((((inputAmount)*((reserveA)/reserveB)))), 5)
        estimate_lpToken = truncate(float((((inputAmount)*(totalSupply)/(reserveB)))), 5)

        result_dic[f"{tokenA}-{tokenB}"] = estimate_lpToken
        result_dic[tokenA] = estimate_reserveA
        result_dic[tokenB] = estimate_reserveB

    return result_dic


def get_remove_liquidity_estimate(env, id, pw, tokenA, tokenB, inputToken, inputAmount):
    
    ks_api.set_env(env)
    dex_api.set_env(env)    
    
    wei = 10**18

    if tokenA == "KSTA":
        tokenA_ = "WKSTA"
    else:
        tokenA_ = tokenA

    if tokenB == "ksETH" or tokenB == "ksUSDT":
        tokenB_ = f"KS"+tokenB[2:]
    else:
        tokenB_ = tokenB
    
    tokenSymbol = f"{tokenA_}_{tokenB_}"    
    login = ks_api.post_otp_login(id,pw, nw=env)
    balance = ks_api.get_balance(login["accessToken"])
    dex_accessKey = ks_api.get_external_accessKey(login["accessToken"])
    dex_login = ks_api.post_dex_login(dex_accessKey["accessKey"])    
    reserve = dex_api.get_pool_reserve(tokenA, tokenB)
    totalSupply = float(dex_api.get_reserveTotalSupply(tokenA, tokenB)["totalSupply"])
    reserveA = float(reserve["reserveA"])
    reserveB = float(reserve["reserveB"])

    # 보유한 LP 수량
    my_lp_balance = truncate(float(get_token(env, balance["address"],"", tokenSymbol)), 5)        
    result_dic = {}    
    data_dic = {}
    if inputToken == f"{tokenA}-{tokenB}":    

        # 소갹할 %
        try:
            burn_per = inputAmount / my_lp_balance
        except(ZeroDivisionError):
            data_dic[f"estimate_remove_lp"] = inputAmount
            data_dic[f"{tokenA}-{tokenB}"] = my_lp_balance     
            result_dic["Result"] = "Fail"
            result_dic["Message"] = "insufficient balance"  
            result_dic["data"] = data_dic
            
            return result_dic

        # 예상 LP 수량
        estimate_lp = truncate(float(inputAmount), 5)
        
        # 예상 ReserveA 수량
        estimate_reserveA_amount = my_lp_balance*reserveA/totalSupply
        estimate_reserveA = truncate(estimate_reserveA_amount*burn_per, 5)

        # 예상 ReserveB 수량
        estimate_reserveB_amount = my_lp_balance*reserveB/totalSupply
        estimate_reserveB = truncate(estimate_reserveB_amount*burn_per, 5)

        data_dic[f"{tokenA}-{tokenB}"] = estimate_lp
        data_dic[tokenA] = estimate_reserveA
        data_dic[tokenB] = estimate_reserveB
        result_dic["Result"] = "Success"
        result_dic["Message"] = "check remove LP estimate"  
        result_dic["data"] = data_dic


    elif inputToken == tokenA:        
        
        estimate_reserveA_amount = my_lp_balance * reserveA / totalSupply        
        # 소각할 %
        burn_per = inputAmount / estimate_reserveA_amount

        # 예상 reserveA 수량
        estimate_reserveA = truncate(inputAmount, 5)        

        # 예상 LP 수량
        estimate_lp = truncate(my_lp_balance * burn_per, 5)

        # 예상 reserveB 수량
        estimate_reserveB_amount = my_lp_balance * reserveB / totalSupply
        estimate_reserveB = truncate(estimate_reserveB_amount * burn_per, 5)

        data_dic[f"{tokenA}-{tokenB}"] = estimate_lp
        data_dic[tokenA] = estimate_reserveA
        data_dic[tokenB] = estimate_reserveB
        result_dic["Result"] = "Success"
        result_dic["Message"] = "check remove LP estimate"  
        result_dic["data"] = data_dic

    elif inputToken == tokenB:  
        
        estimate_reserveB_amount = my_lp_balance * reserveB / totalSupply

        # 소각할 %        
        burn_per = inputAmount / estimate_reserveB_amount

        # 예상 reserveB 수량
        estimate_reserveB = truncate(inputAmount, 5)

        # 예상 LP 수량        
        estimate_lp = truncate(my_lp_balance * burn_per, 5)

        # 예상 reserveA 수량        
        estimate_reserveA_amount = my_lp_balance * reserveA / totalSupply        
        estimate_reserveA = truncate(estimate_reserveA_amount * burn_per, 5)

        data_dic[f"{tokenA}-{tokenB}"] = estimate_lp
        data_dic[tokenA] = estimate_reserveA
        data_dic[tokenB] = estimate_reserveB
        result_dic["Result"] = "Success"
        result_dic["Message"] = "check remove LP estimate"  
        result_dic["data"] = data_dic

    return result_dic


# dex Pool 정보
def get_pool_info(env):
    
    api_url = ""
    headers = {
        'accept' : 'application/json',        
        'Content-Type' : 'application/json'
    }
    prams = {"env" : env}
    response = requests.get(api_url, headers=headers, params = prams)
    res = json.loads(response.text)
    result_dic = {}
    result_dic["statusCode"] = response.status_code

    if response.status_code == 200 or response.status_code == 400:
        data = res.get('resultMessage')                  
        for key, val in data.items():              
            result_dic[key] = val
    else:
        print("Error code : ",response.status_code) 
    return result_dic


# ksta-{token} total staked 확인
def get_total_staked(env, reserveA, reserveB, totalSupply, tokenB): # Liquidity $ 수량으로 Total Skated를 예상
    if env == "stg":
        pair_list_url = ''
    elif env == "prd":
        pair_list_url = ''

    response = requests.get(pair_list_url)    
    data = response.json()
    wei7 = 10000000
    wei = 1000000000000000000
    
    for item in data :
        if item.get('token_b_name') == tokenB:
            total_liquidity_usd = item.get('total_liquidity_usd')            
            multiplier = item.get('multiplier')            
            break

    liquidity_usd = float(total_liquidity_usd / wei7)

    reserve_a = float(reserveA)
    reserve_b = float(reserveB)
    totalsupply = float (totalSupply)
    
    token_B_usd = 1 * ((reserve_a * wei) / (reserve_b * wei))
    total_lp_usd = ((reserve_a * 1) / wei)+((reserve_b * token_B_usd) / wei)    
    
    lp_ratio = liquidity_usd/total_lp_usd
    lp_staked = lp_ratio * totalsupply
    lp_staked = lp_staked/wei

    return lp_staked, liquidity_usd

# ksta-{token} apr 계산
def ksta_pair_apr(total_alloc_point, alloc_point, regularRewardperBlock, total_lp_staked, reward_reserveA, reward_reserveB, totalSupply, reserveA, reserveB):

    wei = 1000000000000000000
    regularRewardperBlock = regularRewardperBlock * 1000000
    block_per_year = (60/1)*60*24*365    
    reward_lpToken_usd = 1 * ((reward_reserveA*wei)/(reward_reserveB*wei)) # 1달러로 계산
    lpToken_usd = 1 * ((reserveA*wei)/(reserveB*wei)) # 1달러로 계산        
    lp_staked = (total_lp_staked)*wei # Stake 한 금액
    a = alloc_point / total_alloc_point * block_per_year * regularRewardperBlock
    b = reward_lpToken_usd    
    c = a*b
    d = (reserveB*wei)*(lp_staked/(totalSupply*wei)) * 2 * (lpToken_usd) # * 100
    apr = ((c/d)) *100            
    
    apr = truncate(apr, 2)

    return apr, lpToken_usd

# # ksta-{token} total staked 최종 확인
def get_totalStaked_apr(env, total_alloc_point, alloc_point, regularRewardperBlock, tokenA, tokenB):
    
    total_alloc_point = total_alloc_point * 10000
    alloc_point = alloc_point * 10000    
    result_dic = {}
    data_dic = {}
    value = get_pool_info(env)
    try:
        # 리워드 받는 토큰 (LOUI)
        reward_reserveA = float(value["KSTA-LOUI_reserve_a"])
        reward_reserveB = float(value["KSTA-LOUI_reserve_b"])
        
        # pair 정보
        totalSupply = float(value[f"{tokenA}-{tokenB}_total_supply"])
        reserveA = float(value[f"{tokenA}-{tokenB}_reserve_a"])
        reserveB = float(value[f"{tokenA}-{tokenB}_reserve_b"])

        total_lp_staked, liquidity_usd = get_total_staked(env, reserveA, reserveB, totalSupply, tokenB)        
        apr, lpToken_usd = ksta_pair_apr(total_alloc_point, alloc_point, regularRewardperBlock, total_lp_staked, reward_reserveA, reward_reserveB, totalSupply, reserveA, reserveB)
        data_dic["total_staked"] = total_lp_staked
        data_dic["apr"] = apr
        data_dic["lpToken_usd"] = lpToken_usd
        data_dic["liquidity_usd"] = liquidity_usd
        result_dic["Result"] = "Success"
        result_dic["Message"] = "check Pair Info"
        result_dic["data"] = data_dic
    except:
        data_dic["total_staked"] = "0"
        data_dic["apr"] = "0"
        data_dic["lpToken_usd"] = "0"
        data_dic["liquidity_usd"] = "0"
        result_dic["Result"] = "Fail"
        result_dic["Message"] = "not found Pair Info"
        result_dic["data"] = data_dic

    return result_dic


########## token #############
# # {token}-{token} lp_usd 계산
def get_token_lp_usd(reserveB_reserveA, reserveB_reserveB, reserveB, totalsupply):
    reserve_a = reserveB_reserveA
    reserve_b = reserveB_reserveB
    wei = 1000000000000000000

    lpToken_usd = 1 * ((reserve_a*wei)/(reserve_b*wei))
    #########lp token usd #########

    staked_lp = 1

    # pair_reserve_a = pool_reserve_a
    pair_reserve_b = reserveB
    pair_total_supply = totalsupply

    total_lp_usd = (pair_reserve_b) * (staked_lp / pair_total_supply) * 2 * lpToken_usd    

    return total_lp_usd

# {token}-{token} liquidity_usd 계산
def get_token_total_liquidity(env, tokenA, tokenB):
    if env == "stg":
        pair_list_url = ''
    else:
        pair_list_url = ''
    response = requests.get(pair_list_url)
    data = response.json()
    # print(data)
    for item in data :
        if item.get('token_a_name') == tokenA:
            if item.get('token_b_name') == tokenB:
                total_liquidity_usd = item.get('total_liquidity_usd')
                total_liquidity_usd = int(total_liquidity_usd) / 10000000
                break
    
    return total_liquidity_usd

# {token}-{token} token apr 계산
def token_pair_apr(total_alloc_point, alloc_point, regularRewardperBlock, total_lp_staked, reward_reserveA, reward_reserveB, reserveB_reserveA, reserveB_reserveB, totalSupply, reserveB):
    
    wei = 1000000000000000000
    block_per_year = (60/1)*60*24*365

    reward_lpToken_usd = 1 * ((reward_reserveA*wei)/(reward_reserveB*wei)) # 1달러로 계산
    lpToken_usd = 1 * ((reserveB_reserveA*wei)/(reserveB_reserveB*wei)) # 1달러로 계산        
    lp_staked = (total_lp_staked)*wei # Stake 한 금액
    a = alloc_point / total_alloc_point * block_per_year * regularRewardperBlock
    b = reward_lpToken_usd
    c = a*b    
    d = (reserveB*wei)*(lp_staked/(totalSupply*wei)) * 2 * (lpToken_usd)
    apr = ((c/d)) *100
    
    apr = truncate(apr, 2)    

    return apr, lpToken_usd

# {token}-{token} token apr 최종 계산
def get_token_totalStaked_apr(env, total_alloc_point, alloc_point, regularRewardperBlock, tokenA, tokenB):
    result_dic = {}
    data_dic = {}
    try:
        value = get_pool_info(env)
        regularRewardperBlock = regularRewardperBlock * 1000000
        total_alloc_point = total_alloc_point * 10000
        alloc_point = alloc_point * 10000

        # 리워드 받는 토큰 (LOUI)
        reward_reserveA = float(value["KSTA-LOUI_reserve_a"])
        reward_reserveB = float(value["KSTA-LOUI_reserve_b"])

        #tokenB reserve
        reserveB_reserveA = float(value[f"KSTA-{tokenB}_reserve_a"])
        reserveB_reserveB = float(value[f"KSTA-{tokenB}_reserve_b"])
        
        #pair totalsupply, reserveB
        totalsupply = float(value[f"{tokenA}-{tokenB}_total_supply"])
        reserveB = float(value[f"{tokenA}-{tokenB}_reserve_b"])
        
        # Token-Token
        lp_usd = get_token_lp_usd(reserveB_reserveA, reserveB_reserveB, reserveB, totalsupply)
        
        lp_liquidity = get_token_total_liquidity(env, tokenA, tokenB)
        
        total_lp_staked = lp_liquidity / lp_usd
        
        apr, lpToken_usd = token_pair_apr(total_alloc_point, alloc_point, regularRewardperBlock, total_lp_staked, reward_reserveA, reward_reserveB, reserveB_reserveA, reserveB_reserveB, totalsupply, reserveB)
        
        data_dic["total_staked"] = total_lp_staked
        data_dic["apr"] = apr
        data_dic["lpToken_usd"] = lpToken_usd
        result_dic["Result"] = "Success"
        result_dic["Message"] = "check Pair Info"
        result_dic["data"] = data_dic
    except:
        data_dic["total_staked"] = "0"
        data_dic["apr"] = "0"
        data_dic["lpToken_usd"] = "0"
        result_dic["Result"] = "Fail"
        result_dic["Message"] = "not found Pair Info"
        result_dic["data"] = data_dic

    return result_dic

def post_swap(env, id, pw, tokenA, tokenB, inputToken, inputAmount, deadline=0, slippage=0.5):
    dex_api.set_env(env)
    ks_api.set_env(env)

    result_dic = {}
    data_dic = {}
    before_dic = {}
    before_reserve_dic = {}
    before_balance_dic = {}
    after_dic = {}
    after_reserve_dic = {}
    after_balance_dic = {}
    estimate_dic = {}

    login = ks_api.post_otp_login(id,pw, nw=env)
    balance = ks_api.get_balance(login["accessToken"])
    dex_accessKey = ks_api.get_external_accessKey(login["accessToken"])
    dex_login = ks_api.post_dex_login(dex_accessKey["accessKey"])        
    
    # 이전 reserveA, B 조회
    before_reserve = dex_api.get_pool_reserve(tokenA, tokenB)
    before_reserveA_amount = truncate(float(before_reserve["reserveA"])/10**18, 5)
    before_reserveB_amount = truncate(float(before_reserve["reserveB"])/10**18, 5)

    # 이전 Token Balance 조회
    if tokenA == "KSTA":        
        before_tokenA_amount = truncate(float(get_coin(env, balance["address"], "Present")), 5)
        
    if tokenB == "KSTA":
        before_tokenB_amount = truncate(float(get_coin(env, balance["address"], "Present")), 5)
        
    if tokenA != "KSTA":
        if tokenA == "ksETH":
            tokenA_ = "KSETH"
        elif tokenA == "ksUSDT":
            tokenA_ = "KSUSDT"
        else:
            tokenA_ = tokenA

        before_tokenA_amount = truncate(float(get_token(env,balance["address"], "", tokenA_)), 5)
        
    if tokenB != "KSTA":           
        if tokenB == "ksETH":
            tokenB_ = "KSETH"            
        elif tokenB == "ksUSDT":
            tokenB_ = "KSUSDT"     
        else:
            tokenB_ = tokenB

        before_tokenB_amount = truncate(float(get_token(env,balance["address"], "", tokenB_)), 5)

    if before_tokenA_amount < inputAmount:
        result_dic["result"] = "Fail"  
        result_dic["message"] = "insufficient balance"  
        data_dic[f"tokenA_Balance"] = before_tokenA_amount        
        result_dic["data"] = data_dic
        
        return result_dic

    # reserveA, reserveB 예상치 조회
    if tokenA == inputToken:
        estimate_amount = dex_api.post_estimateOut(tokenA, tokenB, inputAmount)        
        tokenA_estimate_amount = inputAmount
        tokenB_estimate_amount = truncate(float(estimate_amount["output_value"])/10000000, 5)

    if tokenB == inputToken:
        estimate_amount = dex_api.post_estimateIn(tokenA, tokenB, inputAmount)    
        tokenA_estimate_amount = truncate(float(estimate_amount["input_value"])/10000000, 5)
        tokenB_estimate_amount = inputAmount

    # post swap    
    if tokenA == "KSTA" or tokenB == "KSTA":
        token_type = "currency"
    else:
        token_type = "token"

    swap_txhash = dex_api.post_swap(dex_login['accessToken'], balance["address"], deadline, tokenA_estimate_amount, tokenB_estimate_amount, slippage, tokenA, tokenB, token_type)
    if swap_txhash["statusCode"] == 200:
        hash = swap_txhash["txhash"]
    else:
        hash = "noHash"

    time.sleep(5)

    # 이후 reserveA, B 조회
    after_reserve = dex_api.get_pool_reserve(tokenA, tokenB)
    after_reserveA_amount = truncate(float(after_reserve["reserveA"])/10**18, 5)
    after_reserveB_amount = truncate(float(after_reserve["reserveB"])/10**18, 5)
    
    # 이후 Token Balance 조회
    if tokenA == "KSTA":        
        after_tokenA_amount = truncate(float(get_coin(env, balance["address"], "Present")), 5)
        
    if tokenB == "KSTA":
        after_tokenB_amount = truncate(float(get_coin(env, balance["address"], "Present")), 5)
        
    if tokenA != "KSTA":
        if tokenA == "ksETH":
            tokenA_ = "KSETH"
        elif tokenA == "ksUSDT":
            tokenA_ = "KSUSDT"
        else:
            tokenB_ = tokenB
        after_tokenA_amount = truncate(float(get_token(env,balance["address"], "", tokenA_)), 5)
        
    if tokenB != "KSTA":   
        if tokenB == "ksETH":
            tokenB_ = "KSETH"
        elif tokenB == "ksUSDT":
            tokenB_ = "KSUSDT"     
        else:
            tokenB_ = tokenB
        after_tokenB_amount = truncate(float(get_token(env,balance["address"], "", tokenB_)), 5)


    if hash != "noHash":
        result_dic["result"] = "Success"  
        result_dic["message"] = "Transaction Success"  

        data_dic["Pool"] = f"{tokenA}-{tokenB}"
        data_dic["txHash"] = hash        

        before_reserve_dic["tokenA"] = before_reserveA_amount
        before_reserve_dic["tokenB"] = before_reserveB_amount
        before_balance_dic["tokenA"] = before_tokenA_amount
        before_balance_dic["tokenB"] = before_tokenB_amount
        before_dic["reserve"] = before_reserve_dic
        before_dic["balance"] = before_balance_dic

        estimate_dic["tokenA"] = tokenA_estimate_amount
        estimate_dic["tokenB"] = tokenB_estimate_amount

        after_reserve_dic["tokenA"] = after_reserveA_amount
        after_reserve_dic["tokenB"] = after_reserveB_amount
        after_balance_dic["tokenA"] = after_tokenA_amount
        after_balance_dic["tokenB"] = after_tokenB_amount
        after_dic["reserve"] = after_reserve_dic
        after_dic["balance"] = after_balance_dic

        data_dic["estimate"] = estimate_dic
        data_dic["before"] = before_dic
        data_dic["after"] = after_dic

        result_dic["data"] = data_dic
        
    else:
        result_dic["result"] = "Fail"  
        result_dic["message"] = "Transaction Fail"  
        data_dic["Pool"] = f"{tokenA}-{tokenB}"        
        data_dic["txHash"] = hash

        before_reserve_dic["tokenA"] = before_reserveA_amount
        before_reserve_dic["tokenB"] = before_reserveB_amount
        before_balance_dic["tokenA"] = before_tokenA_amount
        before_balance_dic["tokenB"] = before_tokenB_amount
        before_dic["reserve"] = before_reserve_dic
        before_dic["balance"] = before_balance_dic

        estimate_dic["tokenA"] = tokenA_estimate_amount
        estimate_dic["tokenB"] = tokenB_estimate_amount

        after_reserve_dic["tokenA"] = after_reserveA_amount
        after_reserve_dic["tokenB"] = after_reserveB_amount
        after_balance_dic["tokenA"] = after_tokenA_amount
        after_balance_dic["tokenB"] = after_tokenB_amount
        after_dic["reserve"] = after_reserve_dic
        after_dic["balance"] = after_balance_dic

        data_dic["estimate"] = estimate_dic
        data_dic["before"] = before_dic
        data_dic["after"] = after_dic

        result_dic["data"] = data_dic

    return result_dic

# token total staked 값 계산
def get_token_total_stake(env, tokenA, tokenB, reserveB_reserveA, reserveB_reserveB, reserveB, totalsupply):
    total_lp_usd = get_token_lp_usd(reserveB_reserveA, reserveB_reserveB, reserveB, totalsupply)
    total_liquidity_usd = get_token_total_liquidity(env, tokenA, tokenB)    

    total_lp_staked = total_liquidity_usd / total_lp_usd

    return total_lp_staked

# ksta로 묶인 LP total staked 값 계산
def currency_total_staked(env, tokens):
    tokenA = "KSTA"
    # tokenB_li = ["LOUI", "inKSTA", "ksUSDT", "ksETH", "NST"]
    tokenB_li = list(tokens)    
    dex_api.set_env(env)
    wei = 10**18
    result_dic = {}
    for tokenB in tokenB_li:
        totalSupply = dex_api.get_reserveTotalSupply(tokenA, tokenB)["ethTotalSupply"]
        reserve = dex_api.get_pool_reserve(tokenA, tokenB)
        reserveA = float(reserve["reserveA"]) / wei
        reserveB = float(reserve["reserveB"]) / wei

        total_staked, liquidity_usd = get_total_staked(env, reserveA, reserveB, totalSupply, tokenB)
        total_staked = total_staked / 1000

        result_dic[f"{tokenA}-{tokenB}"] = total_staked

    return result_dic

# token list로 total staked 전체 조회
def token_total_staked(env, aTokens, bTokens):
    wei = 10**18
    tokenA_li = list(aTokens)
    tokenB_li = list(bTokens)
    dex_api.set_env(env)
    result_dic = {}
    for i in range(len(tokenA_li)):
        tokenA = tokenA_li[i]
        tokenB = tokenB_li[i]
        totalSupply = dex_api.get_reserveTotalSupply(tokenA, tokenB)["ethTotalSupply"]
        reserve = dex_api.get_pool_reserve(tokenA, tokenB)
        reserveB_ = dex_api.get_pool_reserve("KSTA", tokenB)        
        reserveB = float(reserve["reserveB"]) / wei
        reserveB_reserveA = float(reserveB_["reserveA"]) / wei
        reserveB_reserveB = float(reserveB_["reserveB"]) / wei

        total_staked = get_token_total_stake(env, tokenA, tokenB, reserveB_reserveA, reserveB_reserveB, reserveB, totalSupply)
        total_staked = total_staked / 1000
        
        result_dic[f"{tokenA}-{tokenB}"] = total_staked

    return result_dic

# single total staked 계산
def single_totalStaked(env, single_token):     
    if env == "prd":
        single_list_url = ''
    elif env == "stg":
        single_list_url = ''
    response = requests.get(single_list_url)
    data = response.json()
    result_dic = {}
    for item in data :
        if item.get('stake_token_symbol') == single_token:
            total_staked_balance = item.get('total_staked_balance')
            break
    total_staked_balance = total_staked_balance/10**7

    result_dic["LOUI-singlePool"] = total_staked_balance

    return result_dic

# Single APR
# yearReward : louiPerblock * (60/comm.BLOCK_TIME_MAP[env.CurrentStage])6024*365
# poolWeight : allocPoint / totalSpecialAllocPoint
# totalLouiPoolEmissionPerYear : (_yearReward * poolWeight) * 10^18
# APR : totalLouiPoolEmissionPerYear / pricePerFullShare / totalShares * 100
def get_single_apr(env, total_alloc, alloc):
    dex_api.set_env(env)
    pricePerFullShare = dex_api.get_price_per_full_share()["pricePerFullShare"]
    totalShares = dex_api.get_total_shares()["totalShares"]
    poolWeight = (alloc / total_alloc) * (alloc*100000)

    yearReward = (60/1)*60*24*365
    totalLouiPoolEmissionPerYear = (yearReward * poolWeight) * 10**18
    apr = totalLouiPoolEmissionPerYear / pricePerFullShare / totalShares * 100
    result_dic = {}
    result_dic["apr"] = truncate(apr, 2)
    
    return result_dic


# Get Token Price
# token 
# network : lbank, coinone
def get_token_price(token='eth-usdt', network='lbank'):
    token_result = {}
    if network == 'lbank':
        url = ""
        response = requests.get(url)

        if response.status_code == 200:
            response_data = response.json()  # JSON 응답인 경우
            token_result['result'] = True
        else:
            print("요청이 실패하였습니다. 상태 코드:", response.status_code)
            token_result['result'] = False
            return token_result
        token_result['network'] = 'LBank'
        token_result['token'] = token
        token_result['price'] = response_data['data'][0]['price']
        return token_result

    elif network == 'coinone':
        url = ""
        headers = {"accept": "application/json"}
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)

        if response.status_code == 200:
            token_result['result'] = True
            price_last = data['tickers'][0]['last']
        else:
            print("요청이 실패하였습니다. 상태 코드:", response.status_code)
            token_result['result'] = False
            return token_result
        token_result['network'] = 'Coin One'
        token_result['token'] = token
        token_result['price'] = price_last
        return token_result
    else:
        token_result['result'] = False
        token_result['network'] = 'Unknown'
        return token_result




######################################
#        T R A N S A C T I O N       #
######################################
# sqeteam1 계정으로 부터 Send KOK
def send_ksta_user(user_id, amount, to_address):
    this_result={}
    if float(amount) > 10000:
        this_result['result'] = False
        this_result['resultMessage'] = '최대 전송 수량은 10,000 KOK 입니다.'    
        return this_result

    sender = 'sqeteam1'
    # SQETEAM1 Amount 확인
    sender_token = ks_api.post_otp_login(sender,pw)
    if sender_token["statusCode"] == 200:
        balance = ks_api.get_balance(sender_token["accessToken"])
        this_result['before_sender_balance'] = balance["KSTA"]
        if float(this_result['before_sender_balance']) < 10000: # 1만 KOK 보다 적음 금액을 가지고 있을 경우, Error
            this_result['result'] = False
            this_result['resultMessage'] = '공급 지갑 Balance 부족'
            return this_result
    else:
        this_result['result'] = False
        this_result['resultMessage'] = '공급 지갑 OTP 로그인 실패'
        return this_result
    # 사용자 Amount 확인
    token = ks_api.post_otp_login(user_id,pw)
    if token["statusCode"] == 200:
        balance = ks_api.get_balance(token["accessToken"])
        this_result['before_user_balance'] = balance["KSTA"]
    else:
        this_result['result'] = False
        this_result['resultMessage'] = 'OTP 로그인 실패'
        return this_result
      
    # to address, 전송 KOK
    send_kok = ks_api.post_sendkok(sender_token["accessToken"], str(amount), to_address)
    if send_kok["statusCode"] == 200:
        txHash = send_kok["transactionHash"]
        time.sleep(5)        
        ex_txhash = ex_api_v2.get_transaction_txhash(txHash)  
        try:
            status = ex_txhash["status"]
        except(KeyError):
            time.sleep(5)
            if env == "stg":
                ex_txhash = ex_api_v2.get_transaction_txhash(txHash)       
        balance = ks_api.get_balance(sender_token["accessToken"])
        this_result['after_sender_balance'] = balance["KSTA"]
        balance = ks_api.get_balance(token["accessToken"])
        this_result['after_user_balance'] = balance["KSTA"]           
        if ex_txhash["status"] == 1:
            time.sleep(2)
            this_result['result'] = True
            this_result['resultMessage'] = '전송 성공'
        else:
            time.sleep(2)
            this_result['result'] = False
            this_result['resultMessage'] = 'TX Hash 확인 실패'
    else:
        balance = ks_api.get_balance(sender_token["accessToken"])
        this_result['after_sender_balance'] = balance["KSTA"]
        balance = ks_api.get_balance(token["accessToken"])
        this_result['after_user_balance'] = balance["KSTA"]  
        time.sleep(2)
        this_result['result'] = False
        this_result['resultMessage'] = '전송 실패'
    return this_result

# send To Community Pool
def send_communityPool(env, id, send_amount):
    ks_api.set_env(env)
    ex_api.set_env(env)
    ex_api_v2.set_env(env)
    token = ks_api.post_otp_login(id,"",nw=env)
    if token["statusCode"] != 200:
        message = "id가 DB에 등록 되어 있는지 확인 해주세요."
        result = "Login Fail"
        
    else:
        balance = ks_api.get_balance(token["accessToken"])    
        pool_balance = ks_api.get_community_balance()
        before_ksta = balance["KSTA"]
        before_sop = balance["SOP"]
        before_cp = pool_balance["balance"]
        str_send_amount = str(send_amount)
        find_dot = str_send_amount.find(".")        
        if float(send_amount) < 10:
            message = "10 KSTA 이상 전송해야 합니다."
            txHash = "None"
            after_cp = "None"
            after_ksta = "None"
            after_sop = "None"
            
            result = [txHash,before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]
        else:
            if len(str_send_amount)-find_dot > 6:
                message = "소수점 5자리 이하로 입력 바랍니다."
                txHash = "None"
                after_cp = "None"
                after_ksta = "None"
                after_sop = "None"
                
                result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]

            else:
                if float(balance["KSTA"]) < 10:
                    message = "보유 금액이 10KSTA 미만 입니다."
                    txHash = "None"
                    after_cp = "None"
                    after_ksta = "None"
                    after_sop = "None"
                    result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]

                else:
                    # 전송 KSTA
                    send_pool = ks_api.post_sendpool(token["accessToken"], str(send_amount))
                    if send_pool["statusCode"] == 200:
                        txHash = send_pool["transactionHash"]
                        time.sleep(5)       
                        if env == "stg":
                            ex_txhash = ex_api_v2.get_transaction_txhash(txHash)     
                            try:
                                status = ex_txhash["status"]
                            except(KeyError):
                                time.sleep(5)
                                if env == "stg":
                                    ex_txhash = ex_api_v2.get_transaction_txhash(txHash) 
                        else:
                            ex_txhash = ex_api.get_txhash_txs(txHash)       
                        if env == "stg":
                            if ex_txhash["status"] == 1:
                                time.sleep(2)
                                after_balance = ks_api.get_balance(token["accessToken"])
                                after_pool_balance = ks_api.get_community_balance()
                                after_ksta = after_balance["KSTA"]
                                after_sop = after_balance["SOP"]
                                after_cp = after_pool_balance["balance"]
                                message = "Transaction Success"
                                result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]

                            else:
                                time.sleep(2)
                                after_balance = ks_api.get_balance(token["accessToken"])
                                after_pool_balance = ks_api.get_community_balance()
                                after_ksta = after_balance["KSTA"]
                                after_sop = after_balance["SOP"]
                                after_cp = after_pool_balance["balance"]
                                message = "Transaction Fail"
                                result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]
                        else:
                            if ex_txhash["status"] == "Success":
                                time.sleep(2)
                                after_balance = ks_api.get_balance(token["accessToken"])
                                after_pool_balance = ks_api.get_community_balance()
                                after_ksta = after_balance["KSTA"]
                                after_sop = after_balance["SOP"]
                                after_cp = after_pool_balance["balance"]
                                message = "Transaction Success"
                                result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]

                            else:
                                time.sleep(2)
                                after_balance = ks_api.get_balance(token["accessToken"])
                                after_pool_balance = ks_api.get_community_balance()
                                after_ksta = after_balance["KSTA"]
                                after_sop = after_balance["SOP"]
                                after_cp = after_pool_balance["balance"]
                                message = "Transaction Fail"
                                result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]
                    else:
                        after_balance = ks_api.get_balance(token["accessToken"])
                        after_pool_balance = ks_api.get_community_balance()
                        after_ksta = after_balance["KSTA"]
                        after_sop = after_balance["SOP"]
                        after_cp = after_pool_balance["balance"]
                        message = "Transaction Fail"
                        txHash = "None"
                        result = [txHash, before_cp,before_ksta,before_sop,after_cp,after_ksta,after_sop]

    return message, result

def send_token(env,tokensymbol, id, toAddress, send_amount):
    ks_api.set_env(env)
    ex_api.set_env(env)
    ex_api_v2.set_env(env)

    token = ks_api.post_otp_login(id,"",nw=env)
    if token["statusCode"] != 200:
        message = "id가 DB에 등록 되어 있는지 확인 해주세요."
        result = "Login Fail"
    else:
        balance = ks_api.get_balance(token["accessToken"])        
        before_ksta = balance["KSTA"]
        before_token = ks_api.get_token_balance(token["accessToken"],tokensymbol)        
        before_token_balance = before_token["balance"]        
        str_send_amount = str(send_amount)
        find_dot = str_send_amount.find(".")        
        
        if len(str_send_amount)-find_dot > 6:
            message = "소수점 5자리 이하로 입력 바랍니다."
            txHash = "None"
            after_ksta = "None"
            after_token_balance = "None"

            result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]
            
        else:         
            if float(before_token_balance) < float(send_amount):
                message = f"보내려는 {tokensymbol} 토큰 잔액이 부족합니다."
                txHash = "None"
                after_ksta = "None"
                after_token_balance = "None"

                result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]
                
            else:
                send_token = ks_api.post_sendToken(token["accessToken"], tokensymbol, str(send_amount), toAddress)                
                if send_token["statusCode"] == 200:
                    txHash = send_token["transactionHash"]
                    time.sleep(5)        
                    if env == "stg":
                        ex_txhash = ex_api_v2.get_transaction_txhash(txHash) 
                        try:
                            status = ex_txhash["status"]
                        except(KeyError):
                            time.sleep(5)
                            if env == "stg":
                                ex_txhash = ex_api_v2.get_transaction_txhash(txHash) 
                        if ex_txhash["status"] == 1:
                            time.sleep(2)
                            after_balance = ks_api.get_balance(token["accessToken"])                    
                            after_ksta = after_balance["KSTA"]
                            after_token = ks_api.get_token_balance(token["accessToken"],tokensymbol)
                            after_token_balance = after_token["balance"]
                            message = "Transaction Success"
                            result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]
                        else:
                            time.sleep(2)
                            after_balance = ks_api.get_balance(token["accessToken"])                    
                            after_ksta = after_balance["KSTA"]
                            after_token = ks_api.get_token_balance(token["accessToken"],tokensymbol)
                            after_token_balance = after_token["balance"]

                            message = "Transaction Fail"
                            result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]
                    else:
                        ex_txhash = ex_api.get_txhash_txs(txHash)   

                        if ex_txhash["status"] == "Success":
                            time.sleep(2)
                            after_balance = ks_api.get_balance(token["accessToken"])                    
                            after_ksta = after_balance["KSTA"]
                            after_token = ks_api.get_token_balance(token["accessToken"],tokensymbol)
                            after_token_balance = after_token["balance"]
                            
                            message = "Transaction Success"
                            result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]

                        else:
                            time.sleep(2)
                            after_balance = ks_api.get_balance(token["accessToken"])                    
                            after_ksta = after_balance["KSTA"]
                            after_token = ks_api.get_token_balance(token["accessToken"],tokensymbol)
                            after_token_balance = after_token["balance"]

                            message = "Transaction Fail"
                            result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]

                else:
                    after_balance = ks_api.get_balance(token["accessToken"])                
                    after_ksta = after_balance["KSTA"]
                    after_token = ks_api.get_token_balance(token["accessToken"],tokensymbol)
                    after_token_balance = after_token["balance"]

                    message = "Transaction Fail"
                    txHash = "None"
                    result = [tokensymbol, txHash, before_ksta, after_ksta, before_token_balance, after_token_balance]
                            
    return message, result

def send_delegate(env, id, so_number, send_amount):
    ks_api.set_env(env)
    ex_api.set_env(env)
    ex_api_v2.set_env(env)

    token = ks_api.post_otp_login(id,"",nw=env)
    if token["statusCode"] != 200:
        message = "id가 DB에 등록 되어 있는지 확인 해주세요."
        result = "Login Fail"
    else:        
        balance = ks_api.get_balance(token["accessToken"])        
        before_ksta = balance["KSTA"]
        before_sop = balance["SOP"]
        so_amount = ks_api.get_my_delegate(balance["address"], so_number)
        before_delegate_amount = so_amount["amount"]

        str_send_amount = str(send_amount)
        find_dot = str_send_amount.find(".")        
        
        if len(str_send_amount)-find_dot > 6:
            message = "소수점 5자리 이하로 입력 바랍니다."
            approve_txHash = "None"
            txHash = "None"
            before_delegate_amount = "None"
            after_ksta = "None"
            after_sop = "None"
            after_delegate_amount = "None"
            result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]
            
        else:         
            if float(send_amount) < 1:
                message = f"위임 시 1이상 위임해야 합니다."
                approve_txHash = "None"
                txHash = "None"
                before_delegate_amount = "None"
                after_ksta = "None"
                after_sop = "None"
                after_delegate_amount = "None"
                result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]
                
            else:
                if float(before_sop) < float(send_amount):
                    message = f"보유 SOP 잔액이 부족합니다."
                    approve_txHash = "None"
                    txHash = "None"
                    before_delegate_amount = "None"
                    after_ksta = "None"
                    after_sop = "None"
                    after_delegate_amount = "None"
                    result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]
                    
                else:
                    so_info = ks_api.get_allInfoV2()
                    for i in so_info:
                        if i["uuid"] == so_number:
                            so_address = i["address_contract"]
                    send_delegate_approve = ks_api.post_delegate_approve(token["accessToken"], so_address, send_amount)
                    if send_delegate_approve["statusCode"] == 200:
                        approve_txHash = send_delegate_approve["transactionHash"]
                        time.sleep(5)       
                        if env == "stg":
                            approve_ex_txhash = ex_api_v2.get_transaction_txhash(approve_txHash)            
                        else:
                            approve_ex_txhash = ex_api.get_txhash_txs(approve_txHash)            
                        time.sleep(2)

                        send_delegate = ks_api.post_delegate(token["accessToken"], so_number, send_amount)
                        if send_delegate["statusCode"] == 200:
                            txHash = send_delegate["transactionHash"]
                            time.sleep(5)        
                            if env == "stg":
                                ex_txhash = ex_api_v2.get_transaction_txhash(txHash)   
                                try:
                                    status = ex_txhash["status"]
                                except(KeyError):
                                    time.sleep(5)
                                    if env == "stg":
                                        ex_txhash = ex_api_v2.get_transaction_txhash(txHash) 
                                if ex_txhash["status"] == 1:
                                    time.sleep(2)
                                    balance = ks_api.get_balance(token["accessToken"])        
                                    after_ksta = balance["KSTA"]
                                    after_sop = balance["SOP"]
                                    so_amount = ks_api.get_my_delegate(balance["address"], so_number)
                                    after_delegate_amount = so_amount["amount"]

                                    message = "Transaction Success"
                                    result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]

                                else:
                                    time.sleep(2)
                                    balance = ks_api.get_balance(token["accessToken"])        
                                    after_ksta = balance["KSTA"]
                                    after_sop = balance["SOP"]
                                    so_amount = ks_api.get_my_delegate(balance["address"], so_number)
                                    after_delegate_amount = so_amount["amount"]

                                    message = "Transaction Fail"
                                    result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]

                            else:
                                ex_txhash = ex_api.get_txhash_txs(txHash)   

                                if ex_txhash["status"] == "Success":
                                    time.sleep(2)
                                    balance = ks_api.get_balance(token["accessToken"])        
                                    after_ksta = balance["KSTA"]
                                    after_sop = balance["SOP"]
                                    so_amount = ks_api.get_my_delegate(balance["address"], so_number)
                                    after_delegate_amount = so_amount["amount"]

                                    message = "Transaction Success"
                                    result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]

                                else:
                                    time.sleep(2)
                                    balance = ks_api.get_balance(token["accessToken"])        
                                    after_ksta = balance["KSTA"]
                                    after_sop = balance["SOP"]
                                    so_amount = ks_api.get_my_delegate(balance["address"], so_number)
                                    after_delegate_amount = so_amount["amount"]

                                    message = "Transaction Fail"
                                    result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]

                        else:
                            time.sleep(2)
                            balance = ks_api.get_balance(token["accessToken"])        
                            after_ksta = balance["KSTA"]
                            after_sop = balance["SOP"]
                            so_amount = ks_api.get_my_delegate(balance["address"], so_number)
                            after_delegate_amount = so_amount["amount"]

                            message = "Transaction Fail"
                            txHash = "None"
                            result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]

                    else:
                        time.sleep(2)
                        balance = ks_api.get_balance(token["accessToken"])        
                        after_ksta = balance["KSTA"]
                        after_sop = balance["SOP"]
                        so_amount = ks_api.get_my_delegate(balance["address"], so_number)
                        after_delegate_amount = so_amount["amount"]

                        message = "Transaction Fail"
                        approve_txHash = "None"
                        txHash = "None"
                        result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]

    return message, result

def claim(address,accessToken,so_id):
    claim_dic = {}
    ks_api.set_env(env)
    claim = float(ks_api.get_my_claim(address, so_id)["reward"])
    if float(claim) == 0:
        claim_dic["claim"] = 0        
    else:        
        ks_api.post_claim(accessToken, so_id)   
        claim_dic["claim"] = float(claim)
    time.sleep(3)

    return claim_dic

def undelegate(address, access_token, amount,so_id, claim_dic):
    ks_api.set_env(env)
    ex_api.set_env(env)
    ex_api_v2.set_env(env)    
    message_dic = {}
    data_dic = {}    
    value_dic = {}

    if claim_dic == "":
        claim_amount = None
    else:
        claim_amount = claim_dic["claim"]
    
    send_undelegate = ks_api.post_undelegate(access_token, so_id, amount)    
    if send_undelegate["statusCode"] == 200:
        txHash = send_undelegate["transactionHash"]
        time.sleep(3)   
        if env == "stg":
            ex_txhash = ex_api_v2.get_transaction_txhash(txHash) 
            try:
                status = ex_txhash["status"]
            except(KeyError):
                time.sleep(3)
                if env == "stg":
                    ex_txhash = ex_api_v2.get_transaction_txhash(txHash)  

            if ex_txhash["status"] == 1:                                
                so_amount = ks_api.get_my_delegate(address, so_id)   
                delegate_amount = so_amount["amount"]
                message_dic["message"] = "Undelegate Success"
                value_dic["undelegate_amount"] = amount
                value_dic["txHash"] = txHash
                value_dic["delegate_amount"] = delegate_amount
                if claim_amount != None:
                    value_dic["claim"] = claim_amount
                data_dic[so_id] = value_dic

            else:                                
                so_amount = ks_api.get_my_delegate(address, so_id)
                delegate_amount = so_amount["amount"]                
                message_dic["message"] = "Undelegate Transaction Fail"
                value_dic["undelegate_amount"] = 0
                value_dic["txHash"] = txHash
                value_dic["delegate_amount"] = delegate_amount
                if claim_amount != None:
                    value_dic["claim"] = claim_amount
                data_dic[so_id] = value_dic
                
        else:
            ex_txhash = ex_api.get_txhash_txs(txHash)            
            if ex_txhash["status"] == "Success":                                
                so_amount = ks_api.get_my_delegate(address, so_id)    
                delegate_amount = so_amount["amount"]                
                message_dic["message"] = "Undelegate Success"
                value_dic["undelegate_amount"] = amount
                value_dic["txHash"] = txHash
                value_dic["delegate_amount"] = delegate_amount
                if claim_amount != None:
                    value_dic["claim"] = claim_amount
                data_dic[so_id] = value_dic            

            else:                
                so_amount = ks_api.get_my_delegate(address, so_id)     
                delegate_amount = so_amount["amount"]                
                message_dic["message"] = "Undelegate Transaction Fail"
                value_dic["undelegate_amount"] = 0
                value_dic["txHash"] = txHash
                value_dic["delegate_amount"] = delegate_amount
                if claim_amount != None:
                    value_dic["claim"] = claim_amount
                data_dic[so_id] = value_dic           

    else:        
        so_amount = ks_api.get_my_delegate(address, so_id)   
        delegate_amount = so_amount["amount"]        
        message_dic["message"] = "Undelegate Fail"
        value_dic["undelegate_amount"] = 0
        value_dic["txHash"] = "None"
        value_dic["delegate_amount"] = delegate_amount
        if claim_amount != None:
            value_dic["claim"] = claim_amount
        data_dic[so_id] = value_dic
    
    return message_dic, data_dic

def send_undelegate(env, id, password, so_id, amount):
    ks_api.set_env(env)
    ex_api.set_env(env)
    ex_api_v2.set_env(env)
    result_dic = {}
    message_dic = {}
    result_data_dic = {}
    message_li = []    
    data_li = []
    data_dic ={}
    value_dic = {}
    
    login = ks_api.post_otp_login(id,password,nw=env)    
    try:
        access_token = login["accessToken"]
    except(KeyError):
        result_dic["result"] = "Fail"
        message_dic["message"] = "login Fail"
        result_data_dic["data"] = "None"
        return result_dic, message_dic, result_data_dic
    
    balance = ks_api.get_balance(access_token)     
    address = balance["address"]
    if float(balance["KSTA"]) < 1:
        result_dic["result"] = "Fail"
        message_dic["message"] = "It is less than 1 KSTA"
        result_data_dic["data"] = "None"
        return result_dic, message_dic, result_data_dic    
    
    if so_id == "":
        so_list = ks_api.get_joinSoList(address)['orgs'] #위임한 SO LIST 추출
        for so_id in so_list:               
            claim_dic = claim(address,access_token,so_id)                     
            so_amount = ks_api.get_my_delegate(address, so_id)['amount']
            
            message_dic, data_dic = undelegate(address, access_token, so_amount,so_id, claim_dic)
            message_li.append(message_dic["message"])          
            data_li.append(data_dic)

        message_dic["message"] = "Undelegate Finish"
        if data_li == []:
            result_data_dic["data"] = "No delegate"
        else:
            result_data_dic["data"] = data_li

        if "Undelegate Fail" in message_li or "Undelegate Transaction Fail" in message_li:
            result_dic["result"] = "Fail"
        else:
            result_dic["result"] = "Success"
        
        return result_dic, message_dic, result_data_dic

    else:        
        so_amount = ks_api.get_my_delegate(address, so_id)             
        before_delegate_amount = float(so_amount["amount"])
        if amount == "":            
            claim_dic = claim(address,access_token,so_id)
            so_amount = ks_api.get_my_delegate(address, so_id)['amount']
            message_dic, data_dic = undelegate(address, access_token, so_amount,so_id, claim_dic)
            if message_dic["message"] == "Undelegate Success":
                result_dic["result"] = "Success"
            else:
                result_dic["result"] = "Fail"

            result_data_dic["data"] = data_dic

            return result_dic, message_dic, result_data_dic
        
        if float(amount) > before_delegate_amount:
            result_dic["result"] = "Fail"
            message_dic["message"] = "Undelegate Fail"
            value_dic["undelegate_amount"] = amount
            value_dic["txHash"] = "None"
            value_dic["delegate_amount"] = before_delegate_amount
            data_dic[so_id] = value_dic
            result_data_dic["data"] = data_dic     

            return result_dic, message_dic, result_data_dic
        
        else:              
            if float(amount) == float(before_delegate_amount):          
                claim_dic = claim(address,access_token,so_id)
            else:
                claim_dic = ""

            message_dic, data_dic = undelegate(address, access_token, amount,so_id, claim_dic)
            if message_dic["message"] == "Undelegate Success":
                result_dic["result"] = "Success"
            else:
                result_dic["result"] = "Fail"

            result_data_dic["data"] = data_dic

            return result_dic, message_dic, result_data_dic

def post_ks_claim(env, accessToken, so_num):
    ex_api.set_env(env)
    ex_api_v2.set_env(env)
    send_claim = ks_api.post_claim(accessToken, so_num)   
    if send_claim["statusCode"] == 200:
        txHash = send_claim["transactionHash"]
        time.sleep(3)        
        if env == "stg":
            ex_txhash = ex_api_v2.get_transaction_txhash(txHash)   
            try:
                status = ex_txhash["status"]
            except(KeyError):
                time.sleep(3)
                if env == "stg":
                    ex_txhash = ex_api_v2.get_transaction_txhash(txHash)  
            if ex_txhash["status"] == 1:
                result = "success"
                return result, txHash                
            else:
                result = "fail"
                return result, txHash                     
        else:
            ex_txhash = ex_api.get_txhash_txs(txHash)            
            if ex_txhash["status"] == "Success":
                result = "success"
                return result, txHash 
            else:
                result = "fail"
                return result, txHash 

def send_claim(env, id, pw, type="", orgId=""):
    data_dic = {}
    message_dic = {}
    result_dic = {}

    ks_api.set_env(env)
    login = ks_api.post_otp_login(id,pw)
    try:
        accessToken = login["accessToken"]
    except(KeyError):
        result_dic["result"] = "Fail"
        message_dic["message"] = "Login Fail"
        data_dic["data"] = "None"        

        return result_dic, message_dic, data_dic
    
    info = ks_api.get_balance(accessToken)
    address = info["address"]
    so_list = ks_api.get_joinSoList(address)['orgs']    
    sort_so_list = sorted(map(int,so_list))    
    if sort_so_list == []:
        result_dic["result"] = "Pass"
        message_dic["message"] = "did not delegate"
        data_dic["data"] = "None"   

        return result_dic, message_dic, data_dic

    total_claim = 0
    claim_dic = {}
    claim_data = {}    
    if type == "":
        if orgId == "":
            result_dic["result"] = "Fail"
            message_dic["message"] = "orgId not entered"
            data_dic["data"] = "None"   

            return result_dic, message_dic, data_dic
        else:
            claim = ks_api.get_my_claim(address, orgId)["reward"]            
            if float(claim) == 0:
                result_dic["result"] = "Success"
                message_dic["message"] = "no claim"
                data_dic["data"] = "None"   

                return result_dic, message_dic, data_dic
            else:
                total_claim += float(claim)                        
                result, txhash = post_ks_claim(env, accessToken, orgId)         
                claim_data["balance"] = float(claim)
                claim_data["transaction_result"] = result
                claim_data["txHash"] = txhash
                claim_dic[str(orgId)] = claim_data

    elif type == "all":
        for so in sort_so_list:
            claim = ks_api.get_my_claim(address, so)["reward"]            
            if float(claim) == 0:
                pass
            else:
                total_claim += float(claim)            
                result, txhash = post_ks_claim(env, accessToken, so)         
                claim_data["balance"] = float(claim)
                claim_data["transaction_result"] = result
                claim_data["txHash"] = txhash
                claim_dic[str(so)] = claim_data
                claim_data = {}
            
    if total_claim == 0:
        result_dic["result"] = "Pass"
        message_dic["message"] = "no claim"          
        data_dic["total_claimAmount"] = total_claim
        data_dic["data"] = claim_dic

    else:
        result_dic["result"] = "Pass"
        message_dic["message"] = "claim success"
        data_dic["total_claimAmount"] = total_claim
        data_dic["data"] = claim_dic

    return result_dic, message_dic, data_dic


######################################
#        SLACK JIRA INTERGRATION     #
######################################

# add this line to point to your certificate path

def get_message_ts(client, channelId, query):
    result_dic = {}
    # conversations_history() 메서드 호출
    result = client.conversations_history(channel=channelId)    
    # 채널 내 메세지 정보 딕셔너리 리스트
    messages = result.data['messages']

    message = list(filter(lambda m: query in m["text"], messages)) # 딕셔너리          
    message_li = message[0]["text"].split("\n")                
    title = message_li[1]
    description_message = ""    
    for i in range(3, len(message_li)):            
        if i == len(message_li)-1:
            description_message += message_li[i]
        else:
            description_message += message_li[i] + "\n"
    description = description_message            

    result_dic["title"] = title
    result_dic["description"] = description    
    
    return result_dic
    
def post_jira(priority):    
    cs_message = get_message_ts(client, channelId, "Title")        
    issue_dict = {
        "project": {"key": "MCBT"},
        "summary": "{}".format(cs_message['title']),
        "description": "{}".format(cs_message['description']),
        "issuetype": {"name": "CS"},
        "priority": {"name": "{}".format(priority)},
        "assignee": {"name": "Unassigned"},
        "components": [{"name": "장애"}]
    }

    jira_client = JIRA(server=jira_server, basic_auth=auth_JIRA)
    try:
        new_issue = jira_client.create_issue(fields=issue_dict) 
        print("create jiraissue")       
        return issue_dict
    except:
        issue_dict = {
                "project": "fail"        
            }
        return issue_dict

def handle_slackEvent(event_data):   
    global ssl_context
    global client
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    client = WebClient(token=slack_token, ssl=ssl_context)    

    event_type = event_data["event"]["type"]       
    if event_type == "reaction_added":
        if event_data["event"]["reaction"] == "issuehigh":    
            print("yeah2")                    
            result = post_jira("High")            
            
        elif event_data["event"]["reaction"] == "issuemedium":                        
            result = post_jira("Medium")
            
        elif event_data["event"]["reaction"] == "issuelow":      
            result = post_jira("Low")

    return result

# MetaMask ERC-20 Token Balance 조회
def get_ethreum_balance(mainnet_prd_wallet, blockNumber=""):
    
    erc_20_balance = {}

    web3_main = Web3(Web3.HTTPProvider(''))
    KSTA_token_address = ""
    USDT_token_address = ""

    with open('erc20.json') as file:
        data = json.load(file)    
    
    KSTA_token_contract = web3_main.eth.contract(address=KSTA_token_address, abi=data)
    USDT_token_contract = web3_main.eth.contract(address=USDT_token_address, abi=data)    
    if blockNumber == None:
        KSTA_balance = KSTA_token_contract.functions.balanceOf(mainnet_prd_wallet).call() / 10**18
        USDT_balance = USDT_token_contract.functions.balanceOf(mainnet_prd_wallet).call() / 10**6
        main_ETH_balance = web3_main.eth.get_balance(mainnet_prd_wallet) / 10**18
    else:
        KSTA_balance = KSTA_token_contract.functions.balanceOf(mainnet_prd_wallet).call({}, blockNumber) / 10**18
        USDT_balance = USDT_token_contract.functions.balanceOf(mainnet_prd_wallet).call({}, blockNumber) / 10**6
        main_ETH_balance = web3_main.eth.get_balance(mainnet_prd_wallet, blockNumber) / 10**18

    erc_20_balance["blockNumber"] = blockNumber
    erc_20_balance["KSTA"] = KSTA_balance
    erc_20_balance["USDT"] = USDT_balance
    erc_20_balance["ETH"] = main_ETH_balance
    return erc_20_balance


######################################
#              EXPLORER              #
######################################

def get_findBlock(env, date_info, resultTime):
    if date_info == None:
        date_info = str((datetime.utcnow() + timedelta(hours=9)).strftime("%Y-%m-%d"))    
    if resultTime == None:
        resultTime = str((datetime.utcnow() + timedelta(hours=9)).strftime("%H:%M:%S"))    
    
    ex_api_v2.set_env(env)
    ex_api.set_env(env)

    if env == "stg":
        block_ = ex_api_v2.get_block_list("1", "1")
        before_blockNumber = block_["blockList"][0]["blockNumber"]        
        before_blockTimeStamp = block_["blockList"][0]["timestamp"]
        
    else:
        block_ = ex_api.get_blocks("1", "1")
        before_blockNumber = block_[0]["blockNumber"]
        before_blockTimeStamp = block_[0]["timeStamp"]

    date_string = "{} {}".format(date_info, resultTime)
    datetime_obj = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
    after_timestamp = time.mktime(datetime_obj.timetuple())

    cal_timestamp = int(before_blockTimeStamp) - int(after_timestamp)
    result_BlockNumber = before_blockNumber - cal_timestamp
    result_dic = {}

    result_dic["date"] = date_info
    result_dic["time"] = resultTime
    result_dic["blockNumber"] = result_BlockNumber
    
    return result_dic


######################################
#               Bridge               #
######################################

def get_tokenBalance(address,block_number,env,token_symbol):
    headers = {
        'accept' : 'application/json'
    }
    if token_symbol == "KSTA":
        api_url = ""
    else:
        api_url = ""

    response = requests.get(api_url, headers=headers)
 
    res = json.loads(response.text) # response.text는 String type임. 이것을 json 형태로 변환
    if response.status_code == 200:
        value = float(res["Value"])
    else:
        value = 0.0
    
    return value

def get_data(len_, env, token_symbol, asset, address, date_):    
    if env == "stg":
        db = pymysql.connect(host=bridge_stg_db, port=3306, user=bridge_stg_myid, passwd=bridge_stg_mypasswd, db='', charset='utf8')
    elif env == "prd":
        db = pymysql.connect(host=bridge_prd_db, port=3306, user=bridge_prd_myid, passwd=bridge_prd_mypasswd, db='', charset='utf8')

    ex_api.set_env(env)
    ex_api_v2.set_env(env)

    if asset == "GND":
        asset = "KS_BESU"        
        if date_ != None:
            if token_symbol == "ALL":
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE updated_at LIKE '{date_}%' \
                        and from_chain_symbol = '{asset}' and sender = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"
            else:
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE updated_at LIKE '{date_}%' \
                        and from_chain_symbol = '{asset}' and token_symbol = '{'ks'+token_symbol}' and sender = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"
        else:
            if token_symbol == "ALL":
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE \
                        from_chain_symbol = '{asset}' and sender = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"
            else:
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE \
                        from_chain_symbol = '{asset}' and token_symbol = '{'ks'+token_symbol}' and sender = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"

    elif asset == "ETH":
        if date_ != None:            
            if token_symbol == "ALL":
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE updated_at LIKE '{date_}%' \
                        and from_chain_symbol = '{asset}' and receiver = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"
            else:
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE updated_at LIKE '{date_}%' \
                        and from_chain_symbol = '{asset}' and token_symbol = '{token_symbol}' and receiver = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"
        else:            
            if token_symbol == "ALL":
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE from_chain_symbol = '{asset}' and receiver = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"
            else:
                sql = f"SELECT token_symbol, from_chain_symbol, to_chain_symbol, sender, receiver, amount, from_chain_htlc_state, to_chain_htlc_state, from_tx_hash, to_tx_hash, updated_at \
                        FROM `kstadium-bridge-web-backend`.history WHERE from_chain_symbol = '{asset}' and token_symbol = '{token_symbol}' and receiver = '{address}' and from_chain_htlc_state = 'withdrawn' and to_chain_htlc_state = 'withdrawn'\
                        order by updated_at DESC ;"

    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    cursor1.execute(sql)
    # 데이타 Fetch
    rows = cursor1.fetchall()
    # print(rows)
    data_dic = {}
    result_dic = {}
    info_dic = {}
    count = 0
    len_rows = len(rows)

    if len_ == "":
        len_ = len_rows
    elif len_rows == 0 or int(len_) > len_rows:
        len_ = len_rows       
    else:
        len_ = int(len_)

    for row in range(len_):        
        count += 1    
        token_symbol = rows[row]["token_symbol"]        
        sender = rows[row]['sender']
        receiver = rows[row]['receiver']
        if token_symbol == "USDT":
            amount = decimal.Decimal(int(rows[row]['amount']) / 10**6)        
        else:
            amount = decimal.Decimal(int(rows[row]['amount']) / 10**18)        

        from_chain_htlc_state = rows[row]['from_chain_htlc_state']
        to_chain_htlc_state = rows[row]['to_chain_htlc_state']
        from_tx_hash = rows[row]['from_tx_hash']
        to_tx_hash = rows[row]['to_tx_hash']
        update_at = rows[row]['updated_at']
        
        if asset == "ETH":
            tx_hash = to_tx_hash              
            if env == "stg":
                block_number = ex_api_v2.get_transaction_txhash(to_tx_hash)["blockNumber"]                
            else:
                block_number = ex_api.get_txhash_txs(to_tx_hash)["blockNumber"]                
            before_block_number = str(int(block_number) -1)
            if token_symbol == "KSTA":    
                token_symbol_ = token_symbol.upper()   
            else:
                token_symbol_ = "KS"+token_symbol.upper()   

            before_balance = get_tokenBalance(address,before_block_number,env,token_symbol_)                
            after_balance = get_tokenBalance(address,block_number,env,token_symbol_)

        elif asset == "KS_BESU":                
            tx_hash = from_tx_hash      
            if env == "stg":
                block_number = ex_api_v2.get_transaction_txhash(from_tx_hash)["blockNumber"]                
            else:
                block_number = ex_api.get_txhash_txs(from_tx_hash)["blockNumber"]                        
            before_block_number = str(int(block_number) -1)
            token_symbol_ = token_symbol.upper()
            before_balance = get_tokenBalance(address,before_block_number,env,token_symbol_)                
            after_balance = get_tokenBalance(address,block_number,env,token_symbol_)
            
        info_dic["update_at"] = update_at.strftime("%Y-%m-%d %H:%M:%S")
        info_dic["token_symbol"] = token_symbol
        info_dic["tx_hash"] = tx_hash  
        info_dic["sender"] = sender
        info_dic["receiver"] = receiver
        info_dic["tx_hash"] = tx_hash        
        info_dic["block_number"] = block_number            
        info_dic["amount"] = amount
        info_dic["before_balance"] = before_balance
        info_dic["after_balance"] = after_balance

        result_dic[str(count)] = info_dic
        info_dic = {}

    data_dic['data'] = result_dic      
    if data_dic['data'] == {}:
        data_dic['data'] = "No Data"     

    return data_dic


######################################
#          SMART CONTRACTS           #
######################################
def sc_get_assert(addr,blocknum='Present',env='stg'):
    result={}

    # 스마트 컨트랙트로 전달할 파라미터 생성
    if env == 'prd':
        sc_nw = 'obtprod'
    elif env == 'stg':
        sc_nw = 'obtstage'
    else:
        result['result'] = False
        result['resultMessage'] = '네트워크 입력이 틀립니다. stg 혹은 prd 중 입력해 주세요.'
        return result
    
    ex_api.set_env(env)
    ex_api_v2.set_env(env)
    if blocknum == 'Present':
        print('*******')
        # 최신 Block을 가져온다
        if env == "stg":
            block_result = ex_api_v2.get_block_list(1,1)
            blocknum = str(block_result['blockList'][0]['blockNumber'])
        else:
            block_result = ex_api.get_blocks(1,1)
            blocknum = str(block_result[0]['blockNumber'])

    # 현재 실행 위치(Swagger) 기록  /Users/medium/autotest/swagger
    current_folder = os.getcwd()
    parent_folder = os.path.dirname(current_folder) + '/kstadium_smartcontract_sqe'
    print(os.getcwd())
    # 실행 위치를 SmartContract로 이동한다. 
    os.chdir(parent_folder)
    print(os.getcwd())

    sc_command = 'FROM_ADDR={} BLOCKNUM={} npx hardhat run --network {} ./test/get_value.ts'.format(addr,blocknum,sc_nw)

    # 쉘 형태로 입력하고 결과를 output에 저장, 문자로 디코딩 후, 라인으로 분리해서 마지막 결과를 추출한다
    output = subprocess.check_output(sc_command, shell=True)
    output_str = output.decode("utf-8")
    lines = output_str.splitlines()
    last_line = lines[3]        
    last_value = last_line.split(' ')[1]

    result["Network"] = env
    result["Block"] = blocknum
    result["Address"] = addr
    result["Value"] = last_value

    # 처음 실행 위치(Swagger)로 이동 /Users/medium/autotest/work-qa/swagger
    os.chdir(current_folder)
    print(os.getcwd())

    return result

def sc_get_token_asset(token_symbol,addr,blocknum='',env='stg'):
    result={}

    # 스마트 컨트랙트로 전달할 파라미터 생성
    if env == 'prd':
        sc_nw = 'obtprod'
    elif env == 'stg':
        sc_nw = 'obtstage'
    else:
        result['result'] = False
        result['resultMessage'] = '네트워크 입력이 틀립니다. stg 혹은 prd 중 입력해 주세요.'
        return result

    # 현재 실행 위치(Swagger) 기록  /Users/medium/autotest/swagger
    current_folder = os.getcwd()
    parent_folder = os.path.dirname(current_folder) + '/kstadium_smartcontract_sqe'
    print(os.getcwd())
    # 실행 위치를 SmartContract로 이동한다.
    os.chdir(parent_folder)
    print(os.getcwd())

    sc_command = 'TOKEN_SYMBOL={} FROM_ADDR={} BLOCKNUM={} npx hardhat run --network {} ./test/get_token.ts'.format(token_symbol, addr,blocknum,sc_nw)
    
    # 쉘 형태로 입력하고 결과를 output에 저장, 문자로 디코딩 후, 라인으로 분리해서 마지막 결과를 추출한다
    output = subprocess.check_output(sc_command, shell=True)
    output_str = output.decode("utf-8")
    lines = output_str.splitlines()
    
    last_line = lines[-1]
    last_value = last_line.split(' ')
    token = last_value[0]
    balance = last_value[2]

    if blocknum == "":
        blocknum = "None"

    result["Network"] = env
    result["Token"] = token
    result["Block"] = blocknum
    result["Address"] = addr
    result["Value"] = balance

    # 처음 실행 위치(Swagger)로 이동
    os.chdir(current_folder)
    print(os.getcwd())

    return result

def sc_get_delegate_claim_asset(addr,blockNumber="",env='stg'):
    result={}

    # 스마트 컨트랙트로 전달할 파라미터 생성
    if env == 'prd':
        sc_nw = 'obtprod'
    elif env == 'stg':
        sc_nw = 'obtstage'
    else:
        result['result'] = False
        result['resultMessage'] = '네트워크 입력이 틀립니다. stg 혹은 prd 중 입력해 주세요.'
        return result

    # 현재 실행 위치(Swagger) 기록  /Users/medium/autotest/swagger
    current_folder = os.getcwd()
    parent_folder = os.path.dirname(current_folder) + '/kstadium_smartcontract_sqe' #이따가 수정해야 함
    print(os.getcwd())    
    os.chdir(parent_folder)
    print(os.getcwd())    

    sc_command = 'FROM_ADDR={} BLOCKNUM={} npx hardhat run --network {} ./test/get_delegate_claim.ts'.format(addr,blockNumber,sc_nw)

    # 쉘 형태로 입력하고 결과를 output에 저장, 문자로 디코딩 후, 라인으로 분리해서 마지막 결과를 추출한다
    output = subprocess.check_output(sc_command, shell=True)
    output_str = output.decode("utf-8")
    soList = output_str.splitlines()
    len_soList = len(soList) #16

    result_li = []
    for i in range(1, len_soList, 3):
        result_dic = {}
        a=i
        b=a+1
        c=b+1            
        result_dic["soId"] = soList[a]        
        result_dic["DelegateAmount"] = str(decimal.Decimal(soList[b])/1000000000000000000)
        result_dic["ClaimAmount"] = str(decimal.Decimal(soList[c])/1000000000000000000)
        result_li.append(result_dic)

    if len(result_li) < 1:
        print("위임한 양이 없습니다.")
    else:
        print(result_li[0])

    os.chdir(current_folder)
    print(os.getcwd())

    return result_li


def sc_get_so_total_delegate(blockNumber="",env='stg'):
    result={}

    # 스마트 컨트랙트로 전달할 파라미터 생성
    if env == 'prd':
        sc_nw = 'obtprod'
    elif env == 'stg':
        sc_nw = 'obtstage'
    else:
        result['result'] = False
        result['resultMessage'] = '네트워크 입력이 틀립니다. stg 혹은 prd 중 입력해 주세요.'
        return result

    # 현재 실행 위치(Swagger) 기록
    current_folder = os.getcwd()
    parent_folder = os.path.dirname(current_folder) + '/kstadium_smartcontract_sqe' 
    os.chdir(parent_folder)    

    sc_command = 'BLOCKNUM={} npx hardhat run --network {} ./test/get_so_delegate.ts'.format(blockNumber,sc_nw)

    # 쉘 형태로 입력하고 결과를 output에 저장, 문자로 디코딩 후, 라인으로 분리해서 마지막 결과를 추출한다
    output = subprocess.check_output(sc_command, shell=True)
    output_str = output.decode("utf-8")
    data_list = output_str.splitlines()    

    len_data_list = len(data_list)

    result_li = []        
    for i in range(1, len_data_list):

        result_dic = {}
        so_id, balance = data_list[i].split(',')        
        result_dic["soId"] = so_id        
        result_dic["total_delegate"] = str(decimal.Decimal(balance)/1000000000000000000)
        result_li.append(result_dic)
        result_dic = {}

    # 처음 실행 위치(Swagger)로 이동
    os.chdir(current_folder)    

    return result_li

def get_flux_address(env, address):
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    id_sql = f"SELECT tmember.user_id , tsom.address , tsom.sop, tsom.claim ,tsom.member_id, tsom.so_id  FROM kstadium_main.som as tsom left join kstadium_main.`member` as tmember on tsom.member_id = tmember.id WHERE tmember.address = '{address}' and tsom.protocol_id =2;"
    cursor1.execute(id_sql)
    datas = cursor1.fetchall()
    so_li = []
    add_li = []    
    for i in datas:
        so_id = str(i["so_id"])
        address = i["address"]
        so_li.append(so_id)
        add_li.append(address)
    
    separator = "','"
    str_so_li = f"'{separator.join(so_li)}'"
    str_add_li = f"'{separator.join(add_li)}'"

    return str_so_li, str_add_li


def sc_get_flux_delegate_claim_asset(so_number, addrs,blockNumber="",env='stg'):
    result={}

    # 스마트 컨트랙트로 전달할 파라미터 생성
    if env == 'prd':
        sc_nw = 'obtprod'
    elif env == 'stg':
        sc_nw = 'obtstage'
    else:
        result['result'] = False
        result['resultMessage'] = '네트워크 입력이 틀립니다. stg 혹은 prd 중 입력해 주세요.'
        return result

    # 현재 실행 위치(Swagger) 기록 
    current_folder = os.getcwd()
    parent_folder = os.path.dirname(current_folder) + '/kstadium_smartcontract_sqe' #이따가 수정해야 함    
    os.chdir(parent_folder)  
    print(os.getcwd())

    sc_command = f'SO_NUM={so_number} FROM_ADDR={addrs} BLOCKNUM={blockNumber} npx hardhat run --network {sc_nw} ./test/get_flux_delegate_claim.ts'

    # 쉘 형태로 입력하고 결과를 output에 저장, 문자로 디코딩 후, 라인으로 분리해서 마지막 결과를 추출한다
    output = subprocess.check_output(sc_command, shell=True)
    output_str = output.decode("utf-8")
    soList = output_str.splitlines()
    len_soList = len(soList) #16   
    
    os.chdir(current_folder)
    print(os.getcwd())
    
    result_li = []
    for i in range(1, len_soList, 3):
        result_dic = {}
        a=i
        b=a+1
        c=b+1                    
        result_dic["soId"] = soList[a]                        
        result_dic["DelegateAmount"] = str(decimal.Decimal(soList[b])/1000000000000000000)
        result_dic["ClaimAmount"] = str(decimal.Decimal(soList[c])/1000000000000000000)
        result_li.append(result_dic)

    if len(result_li) < 1:
        print("위임한 양이 없습니다.")
    else:
        print(result_li[0])

    os.chdir(current_folder)
    print(os.getcwd())

    return result_li


######################################
#                Q A                 #
######################################

# MetaMask ERC-20 Token Balance 조회
def get_mainnet_erc20_balance(mainnet_prd_wallet, blockNumber=""):
    
    erc_20_balance = {}

    web3_main = Web3(Web3.HTTPProvider(''))
    KSTA_token_address = ""
    USDT_token_address = ""

    with open('erc20.json') as file:
        data = json.load(file)    
    
    KSTA_token_contract = web3_main.eth.contract(address=KSTA_token_address, abi=data)
    USDT_token_contract = web3_main.eth.contract(address=USDT_token_address, abi=data)    
    if blockNumber == "":
        KSTA_balance = KSTA_token_contract.functions.balanceOf(mainnet_prd_wallet).call() / 10**18
        USDT_balance = USDT_token_contract.functions.balanceOf(mainnet_prd_wallet).call() / 10**6
        main_ETH_balance = web3_main.eth.get_balance(mainnet_prd_wallet) / 10**18
    else:
        KSTA_balance = KSTA_token_contract.functions.balanceOf(mainnet_prd_wallet).call({}, blockNumber) / 10**18
        USDT_balance = USDT_token_contract.functions.balanceOf(mainnet_prd_wallet).call({}, blockNumber) / 10**6
        main_ETH_balance = web3_main.eth.get_balance(mainnet_prd_wallet, blockNumber) / 10**18

    erc_20_balance["blockNumber"] = blockNumber
    erc_20_balance["KSTA"] = KSTA_balance
    erc_20_balance["USDT"] = USDT_balance
    erc_20_balance["ETH"] = main_ETH_balance
    return erc_20_balance

def get_coin(env,address, blockNumber):
    api_url = ""
    headers = {
        'accept' : 'application/json',
        'Content-Type' : 'application/json'
    }
    response = requests.get(api_url, headers=headers)
    res = json.loads(response.text)
    # print(res.get('Value'))
    return res.get('Value')

def get_token(env,address, blockNumber, tokenSymbol):
    api_url = ""
    headers = {
        'accept' : 'application/json',
        'Content-Type' : 'application/json'
    }
    response = requests.get(api_url, headers=headers)
    res = json.loads(response.text)    
    return res.get('Value')

def get_kstadium_balance(env, address, blockNumber):
    GND_balance = {}
    ksta = get_coin(env,address, blockNumber)
    eth = get_token(env,address, blockNumber, "KSETH")
    usdt = get_token(env,address, blockNumber, "KSUSDT")

    GND_balance["blockNumber"] = blockNumber
    GND_balance["KSTA"] = ksta
    GND_balance["ksETH"] = eth
    GND_balance["ksUSDT"] = usdt

    return GND_balance

def get_gnd_blockNumber(date_info, resultTime):
    if date_info == "":
        date_info = str((datetime.utcnow() + timedelta(hours=9)).strftime("%Y-%m-%d"))    
    if resultTime == "":
        resultTime = str((datetime.utcnow() + timedelta(hours=9)).strftime("%H:%M:%S"))    
    
    ex_api.set_env("prd")
    block_ = ex_api.get_blocks("1", "1")
    before_blockNumber = block_[0]["blockNumber"]
    before_blockTimeStamp = block_[0]["timeStamp"]

    date_string = "{} {}".format(date_info, resultTime)
    datetime_obj = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
    after_timestamp = time.mktime(datetime_obj.timetuple())

    cal_timestamp = int(before_blockTimeStamp) - int(after_timestamp)
    result_BlockNumber = before_blockNumber - cal_timestamp
    result_dic = {}

    result_dic["blockNumber"] = result_BlockNumber
    
    return result_dic

def get_eth_blockNumber(date_info, resultTime, eterscan_api_key):

    date_string = "{} {}".format(date_info, resultTime)
    datetime_obj = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')      
    utc_time = str(datetime_obj) # + timedelta(hours=9))
    utc_time_obj = datetime.strptime(utc_time, '%Y-%m-%d %H:%M:%S')
    
    timestemp = int(utc_time_obj.timestamp())    
    
    api_url = ""
    headers = {
        'accept' : 'application/json',
        'Content-Type' : 'application/json'
    }
    response = requests.get(api_url, headers=headers)
    res = json.loads(response.text)    
    return int(res.get('result'))



# date = "2023-07-19"
# startTime = "10:00:00"
# endTime = "11:00:00"
# return blockNumber, KSTA, USDT, ETH, 
def get_eth_gnd_balance(date, startTime, endTime):    
    result_dic = {}
    balance_dic = {}
    env = "prd"
    start_eth_blockNumber = get_eth_blockNumber(date, startTime, eterscan_api_key)
    start_gnd_block_number = get_gnd_blockNumber(date, startTime)         
    start_erc_20_balance = get_mainnet_erc20_balance(mainnet_prd_wallet, start_eth_blockNumber)
    start_kstadium_balance = get_kstadium_balance(env, address, start_gnd_block_number['blockNumber'])
    
    end_eth_blockNumber = get_eth_blockNumber(date, endTime, eterscan_api_key)
    end_gnd_block_number = get_gnd_blockNumber(date, endTime)         
    end_erc_20_balance = get_mainnet_erc20_balance(mainnet_prd_wallet, end_eth_blockNumber)
    end_kstadium_balance = get_kstadium_balance(env, address, end_gnd_block_number['blockNumber'])

    balance_dic["ETH_blockNumber"] = start_erc_20_balance['blockNumber']
    balance_dic["ETH_KSTA"] = start_erc_20_balance['KSTA']
    balance_dic["ETH_USDT"] = start_erc_20_balance['USDT']
    balance_dic["ETH_ETH"] = start_erc_20_balance['ETH']

    balance_dic["GND_blockNumber"] = start_kstadium_balance['blockNumber']
    balance_dic["GND_KSTA"] = start_kstadium_balance['KSTA']
    balance_dic["GND_ksUSDT"] = start_kstadium_balance['ksUSDT']
    balance_dic["GND_ksETH"] = start_kstadium_balance['ksETH']
    result_dic["before"] = balance_dic

    balance_dic = {}

    balance_dic["ETH_blockNumber"] = end_erc_20_balance['blockNumber']
    balance_dic["ETH_KSTA"] = end_erc_20_balance['KSTA']
    balance_dic["ETH_USDT"] = end_erc_20_balance['USDT']
    balance_dic["ETH_ETH"] = end_erc_20_balance['ETH']

    balance_dic["GND_blockNumber"] = end_kstadium_balance['blockNumber']
    balance_dic["GND_KSTA"] = end_kstadium_balance['KSTA']
    balance_dic["GND_ksUSDT"] = end_kstadium_balance['ksUSDT']
    balance_dic["GND_ksETH"] = end_kstadium_balance['ksETH']
    result_dic["after"] = balance_dic

    return result_dic

# SOP 삭감 관련
def db_connect(env):
    if env == "prd":
        # # #prd
        kstadium_rest_api = ''
        myid = ''
        mypasswd = ''
        db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
    elif env == "stg":
        # 2. 접속하기
        kstadium_rest_api = ''
        myid = ''
        mypasswd = ''
        db = pymysql.connect(host=kstadium_rest_api, port=3306, user=myid, passwd=mypasswd, db='', charset='utf8')
    
    return db


def get_google_sheetKey():
    current_folder = os.getcwd()
    parent_folder = os.path.dirname(current_folder) + '/google'
    print(os.getcwd())

    os.chdir(parent_folder)
    file_path = os.getcwd()
    print(os.getcwd())

    zip_file = zipfile.ZipFile(file_path + "/sheetKey.zip", "w")
    for (path, dir, files) in os.walk(file_path):
        # print(files)
        for file in files:
            if file.endswith('.json'):
                print(file)
                zip_file.write(file)

    zip_file.close()

    os.chdir(current_folder)
    print(os.getcwd())

    zip_name = "/sheetKey.zip"
    zip_path = file_path + "/sheetKey.zip"

    return zip_name, zip_path

# Git Tag 정보를 가져온다.
def get_tags():
    # GitHub API 엔드포인트
    repo_owner = ''  # 깃허브 사용자 또는 조직 이름
    repo_name_li = ['']
    github_token = ''
    data_li = []
    for repo_name in repo_name_li:
        stg_ver = stg_date = ''
        prd_ver = prd_date = '' 

        url = ''

        # GitHub API에 GET 요청을 보내서 태그 정보 가져오기
        headers = {'Authorization': f'token {github_token}'}

        # 모든 태그 정보를 저장할 빈 리스트
        all_tags = []

        # GitHub API에서 페이지네이션을 사용하여 모든 태그 가져오기
        page = 1
        while True:
            response = requests.get(url, headers={"Authorization": f"token {github_token}"}, params={"page": page})
            if response.status_code == 200:
                tags = response.json()
                if not tags:
                    break  # 더 이상 태그가 없으면 반복 중단
                all_tags.extend(tags)
                page += 1
            else:
                print(f"Failed to fetch tags from GitHub API. Status code: {response.status_code}")
                break

        versions = []
        # # 모든 태그 정보 출력
        for tag in all_tags:
            # print(tag['name'])
            versions.append(tag['name'])

        # "v"로 시작하는 버전과 "r"로 시작하는 버전을 분리
        v_versions = [ver for ver in versions if ver.startswith("v")]
        r_versions = [ver for ver in versions if ver.startswith("r")]

        # Prd 가장 높은 버전 찾기
        try:
            version_pattern = r'v(\d+\.\d+\.\d+)'
            valid_versions = [match.group(1) for ver in v_versions for match in re.finditer(version_pattern, ver)]
            highest_version = max(valid_versions, key=lambda x: tuple(map(int, x.split('.'))))
            prd_ver = 'v'+highest_version
        except ValueError as e:
            print(f'PRD {repo_name} version : {e}')
            prd_ver = ''

        # Stg 가장 높은 버전 찾기
        try:
            version_pattern = r'r(\d+\.\d+\.\d+)'
            valid_versions = [match.group(1) for ver in r_versions for match in re.finditer(version_pattern, ver)]
            highest_version = max(valid_versions, key=lambda x: tuple(map(int, x.split('.'))))
            stg_ver = 'r'+highest_version
        except ValueError as e:
            print(f'STG {repo_name} version : {e}')
            stg_ver = ''

        for tag in all_tags:
            if tag["name"] == prd_ver:
                commit_url = tag["commit"]["url"]
                commit_response = requests.get(commit_url, headers=headers)
                commit_data = commit_response.json()
                prd_date = commit_data["commit"]["committer"]["date"]
            elif tag["name"] == stg_ver:
                commit_url = tag["commit"]["url"]
                commit_response = requests.get(commit_url, headers=headers)
                commit_data = commit_response.json()
                stg_date = commit_data["commit"]["committer"]["date"]


        data_li.append({'Repository':repo_name, 'Latest_PRD_Version':prd_ver, 'DATE_PRD':prd_date, 'Latest_STG_Version':stg_ver, 'DATE_STG':stg_date})

    return data_li


def get_tags_for_repo(repo_name):
    repo_owner = ''
    github_token = ''
    stg_ver = stg_date = ''
    prd_ver = prd_date = '' 

    url = ''

    # GitHub API에 GET 요청을 보내서 태그 정보 가져오기
    headers = {'Authorization': f'token {github_token}'}

    # 모든 태그 정보를 저장할 빈 리스트
    all_tags = []

    # GitHub API에서 페이지네이션을 사용하여 모든 태그 가져오기
    page = 1
    while True:
        response = requests.get(url, headers={"Authorization": f"token {github_token}"}, params={"page": page})
        if response.status_code == 200:
            tags = response.json()
            if not tags:
                break  # 더 이상 태그가 없으면 반복 중단
            all_tags.extend(tags)
            page += 1
        else:
            print(f"Failed to fetch tags from GitHub API. Status code: {response.status_code}")
            break

    versions = []
    # # 모든 태그 정보 출력
    for tag in all_tags:
        # print(tag['name'])
        versions.append(tag['name'])

    # "v"로 시작하는 버전과 "r"로 시작하는 버전을 분리
    v_versions = [ver for ver in versions if ver.startswith("v")]
    r_versions = [ver for ver in versions if ver.startswith("r")]

    # Prd 가장 높은 버전 찾기
    try:
        version_pattern = r'v(\d+\.\d+\.\d+)'
        valid_versions = [match.group(1) for ver in v_versions for match in re.finditer(version_pattern, ver)]
        highest_version = max(valid_versions, key=lambda x: tuple(map(int, x.split('.'))))
        prd_ver = 'v'+highest_version
    except ValueError as e:
        print(f'PRD {repo_name} version : {e}')
        prd_ver = ''

    # Stg 가장 높은 버전 찾기
    try:
        version_pattern = r'r(\d+\.\d+\.\d+)'
        valid_versions = [match.group(1) for ver in r_versions for match in re.finditer(version_pattern, ver)]
        highest_version = max(valid_versions, key=lambda x: tuple(map(int, x.split('.'))))
        stg_ver = 'r'+highest_version
    except ValueError as e:
        print(f'STG {repo_name} version : {e}')
        stg_ver = ''

    for tag in all_tags:
        if tag["name"] == prd_ver:
            commit_url = tag["commit"]["url"]
            commit_response = requests.get(commit_url, headers=headers)
            commit_data = commit_response.json()
            prd_date = commit_data["commit"]["committer"]["date"]
        elif tag["name"] == stg_ver:
            commit_url = tag["commit"]["url"]
            commit_response = requests.get(commit_url, headers=headers)
            commit_data = commit_response.json()
            stg_date = commit_data["commit"]["committer"]["date"]

    return {'Repository': repo_name, 'Latest_PRD_Version': prd_ver, 'DATE_PRD': prd_date, 'Latest_STG_Version': stg_ver, 'DATE_STG': stg_date}

def get_tags_v2():
    repo_name_li = ['']
    
    # Create a multiprocessing Pool
    pool = Pool()

    # Use the Pool to apply the function to each repository in parallel
    results = pool.map(get_tags_for_repo, repo_name_li)

    # Close the pool to free up resources
    pool.close()
    pool.join()

    return results


######################################
#               MONGO                 #
######################################

# env = 'stg'
# date_info = "2023-07-24"
# return checkpoint, blockNumber, createdAt
def get_checkpoints(env, date_info):
    
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['checkpoints']

    # 입력된 date 값을 변환. 
    # checkpoint의 createdAt이 UTC 기준으로 적재되어 -1day 값으로 조회해야함.
    input_date = datetime.strptime(date_info, "%Y-%m-%d")
    start_date = input_date - timedelta(days=1)
    end_date = start_date + timedelta(days=1)

    # 쿼리문 실행
    query_results = collection.find({"createdAt": {"$gte": start_date, "$lt": end_date}})
    result = []
    for data in query_results:
        result_dic = {}
        result_dic['checkpoint'] = str(data['_id'])
        result_dic['blockNumber'] = data['blockNumber']
        result_dic['createdAt'] = str(data['createdAt'])
        result.append(result_dic)

    # 쿼리문의 결과를 dic형태로 반환
    return result

# env = 'stg'
# date_info = "2023-07-24"
# return checkpoint, blockCount, blockInflation, transactionCount,fee, soReward, communityReward, devReward, createdAt
def get_inflations(env, date_info):

    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']
    
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['inflations']

    # 쿼리문 실행
    query_results = collection.find({'checkpoint':ObjectId(checkpoint)})
    result = []
    for data in query_results:
        result_dic = {}
        result_dic['checkpoint'] = str(data['checkpoint'])
        result_dic['blockCount'] = data['blockCount']
        result_dic['blockInflation'] = data['blockInflation']
        result_dic['transactionCount'] = data['transactionCount']
        result_dic['fee'] = data['fee']
        result_dic['soReward'] = data['soReward']
        result_dic['communityReward'] = data['communityReward']
        result_dic['devReward'] = data['devReward']
        result_dic['createdAt'] = str(data['createdAt'])
        result.append(result_dic)

    # 쿼리문의 결과를 dic형태로 반환
    return result


# env = 'stg'
# date_info = "2023-07-24"
# return checkpoint, soId, name, ranking, sop, ratio, claim, contract, leader, createdAt
def get_so_snapshots(env, date_info):

    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']
    
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['so_snapshots']

    # 쿼리문 실행
    query_results = collection.find({'checkpoint':ObjectId(checkpoint)})

    result = []
    for data in query_results:
        result_dic = {}
        result_dic['checkpoint'] = str(data['checkpoint'])
        result_dic['soId'] = data['soId']
        result_dic['name'] = data['name']
        result_dic['ranking'] = data['ranking']
        result_dic['sop'] = data['sop']
        result_dic['ratio'] = data['ratio']
        result_dic['claim'] = data['claim']
        result_dic['contract'] = data['contract']
        result_dic['leader'] = data['leader']
        result_dic['createdAt'] = str(data['createdAt'])
        result.append(result_dic)

    # soId 순으로 리스트 재정렬
    result = sorted(result, key=lambda x: x['soId'])

    # 쿼리문의 결과를 dic형태로 반환
    return result


# env = 'stg'
# date_info = "2023-07-24"
# return checkpoint, soId, memberId, protocolId, address, sop, ratio, claim, createdAt
def get_som_snapshots(env, date_info):
    
    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']
    
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['som_snapshots']

    # 쿼리문 실행
    query_results = list(collection.find({'checkpoint':ObjectId(checkpoint)}))
    
    # Prepare a list of memberIds to fetch user_ids in a single SQL query
    try:
        member_ids = [str(data['memberId']) for data in query_results if 'memberId' in data]
    except KeyError:
        print(f"Missing key for checkpoint {data['checkpoint']}")

    # Connect to MySQL database
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)

    # Fetch user_ids for all memberIds in a single query
    member_ids_str = "','".join(member_ids)
    sql = f"SELECT id, user_id FROM kstadium_main.`member` WHERE id IN ('{member_ids_str}');"
    cursor1.execute(sql)
    rows = cursor1.fetchall()
    member_to_user = {row['id']: row['user_id'] for row in rows}

    result = []
    for data in query_results:
        try:
            result_dic = {
                'checkpoint': str(data['checkpoint']),
                'soId': data['soId'],
                'protocolId': data['protocolId'],
                'address': data['address'],
                'memberId': data['memberId'],
                'user_id': str(member_to_user[data['memberId']]),
                'sop': data['sop'],
                'ratio': data['ratio'],
                'claim': data['claim'],
                'createdAt': str(data['createdAt'])
            }
            result.append(result_dic)
        except KeyError:
            print(f"Missing key for checkpoint {data['checkpoint']}")

    # Sort the list by soId
    result = sorted(result, key=lambda x: x['soId'])

    return result



# env = 'stg'
# date_info = "2023-07-24"
# return checkpoint, soId, reward, basicReward, blockReward, rankReward, leaderReward, memberReward, createdAt
def get_so_rewards(env, date_info):

    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']
    
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['so_rewards']

    # 쿼리문 실행
    query_results = collection.find({'checkpoint':ObjectId(checkpoint)})

    result = []
    for data in query_results:
        result_dic = {}
        result_dic['checkpoint'] = str(data['checkpoint'])
        result_dic['soId'] = data['soId']
        result_dic['reward'] = data['reward']
        result_dic['basicReward'] = data['basicReward']
        result_dic['blockReward'] = data['blockReward']
        result_dic['rankReward'] = data['rankReward']
        result_dic['leaderReward'] = data['leaderReward']
        result_dic['memberReward'] = data['memberReward']
        result_dic['createdAt'] = str(data['createdAt'])
        result.append(result_dic)

    # soId 순으로 리스트 재정렬
    result = sorted(result, key=lambda x: x['soId'])

    # 쿼리문의 결과를 dic형태로 반환
    return result

# env = 'stg'
# date_info = "2023-07-24"
# return checkpoint, soId, memberId, protocolId, address, reward, createdAt
def get_som_rewards(env, date_info):
    
    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']
    
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['som_rewards']

    # 쿼리문 실행
    query_results = list(collection.find({'checkpoint':ObjectId(checkpoint)}))
    
    # Prepare a list of memberIds to fetch user_ids in a single SQL query
    try:
        member_ids = [str(data['memberId']) for data in query_results if 'memberId' in data]
    except KeyError:
        print(f"Missing key for checkpoint {data['checkpoint']}")

    # Connect to MySQL database
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)

    # Fetch user_ids for all memberIds in a single query
    member_ids_str = "','".join(member_ids)
    sql = f"SELECT id, user_id FROM kstadium_main.`member` WHERE id IN ('{member_ids_str}');"
    cursor1.execute(sql)
    rows = cursor1.fetchall()
    member_to_user = {row['id']: row['user_id'] for row in rows}

    result = []
    for data in query_results:
        try:
            result_dic = {
                'checkpoint': str(data['checkpoint']),
                'soId': data['soId'],
                'protocolId': data['protocolId'],
                'address': data['address'],
                'memberId': data['memberId'],
                'user_id': str(member_to_user[data['memberId']]),
                'reward': data['reward'],
                'createdAt': str(data['createdAt'])
            }
            # print(result_dic['address'])
            result.append(result_dic)

        except KeyError:
            print(f"Missing key for checkpoint {data['checkpoint']}")

    # Sort the list by soId
    result = sorted(result, key=lambda x: x['soId'])

    return result

# env = 'stg'
# date_info = "2023-08-10"
# return functionName, hash, blockNumber, from, to, value, fee, createdAt, updatedAt
def get_transaction_investment(env, user_id):
   
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)

    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    
    # 데이터베이스 선택
    db = client['kstadium_main']

    # 컬렉션 선택
    collection = db['transactions']

    address = check_user_address(user_id, env)

    # 쿼리문 실행
    query_results = collection.find({"functionName":'investment', "from":f'{address}'})

    result = []
    for doc in query_results:
        result_dic = {}
        result_dic['functionName']= doc['functionName']
        result_dic['hash'] = doc['hash']
        result_dic['blockNumber'] = doc['blockNumber']
        result_dic['from'] = doc['from']
        result_dic['to'] = doc['to']
        result_dic['amount'] = doc['value']
        result_dic['fee'] = doc['fee']
        result_dic['createdAt'] = doc['createdAt']
        result_dic['updatedAt'] = doc['updatedAt']
        result.append(result_dic)
    
    result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)

    return result


# env = 'stg'
# date_info = "2023-08-10"
# return functionName, hash, blockNumber, from, to, uuid, amount, fee, createdAt, updatedAt
def get_transaction_undelegate(env, user_id, type_):
   
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['transactions']
    # address 조회
    address = check_user_address(user_id, env)

    orgsmgr = contract_address(env)[0]
    flux_controller = contract_address(env)[1]

    if type_ == 'App':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'undelegate', "to": orgsmgr ,"from":f'{address}'}))

        result = []
        for doc in query_results:
            result_dic = {}
            result_dic['functionName'] = doc.get('functionName')
            result_dic['hash'] = doc.get('hash')
            result_dic['blockNumber'] = doc.get('blockNumber')
            result_dic['from'] = doc.get('from')
            result_dic['to'] = doc.get('to')
            
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'UndelegateEvent':
                    params = event_log.get('params', [])
                    result_dic['orgId'] = params[0].get('value')

            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic['amount'] = params[2].get('value')

            result_dic['fee'] = doc.get('fee')
            result_dic['createdAt'] = doc.get('createdAt')
            result_dic['updatedAt'] = doc.get('updatedAt')
            
            result.append(result_dic)
        
        result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)
        
        return result

    elif type_ == 'Flux':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'undelegate', "to": flux_controller ,"from":f'{address}'}))
        result = []

        for doc in query_results:
            result_dic = {}
            result_dic['functionName'] = doc.get('functionName')
            result_dic['hash'] = doc.get('hash')
            result_dic['blockNumber'] = doc.get('blockNumber')
            result_dic['from'] = doc.get('from')
            result_dic['to'] = doc.get('to')
            
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'UnDelegate':
                    params = event_log.get('params', [])
                    result_dic['orgId'] = params[1].get('value')
                    result_dic['amount'] = params[3].get('value')

            result_dic['fee'] = doc.get('fee')
            result_dic['createdAt'] = doc.get('createdAt')
            result_dic['updatedAt'] = doc.get('updatedAt')
            
            result.append(result_dic)
        
        result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)

        return result

# env = 'stg'
# date_info = "2023-08-18"
# return accumulate_undelegate
def get_transaction_accumulate_undelegate(env, type_):
   
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['transactions']

    sum_amount = 0  # 합계를 저장할 변수

    orgsmgr = contract_address(env)[0]
    flux_controller = contract_address(env)[1]

    if type_ == 'App':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'undelegate', "to": orgsmgr}))

        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[2].get('value')
                    sum_amount += int(result_dic['amount'])  # 합계에 누적

        return sum_amount  # 합계 반환

    elif type_ == 'Flux':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'undelegate', "to":flux_controller}))

        sum_amount = 0  # 합계를 저장할 변수

        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'UnDelegate':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[3].get('value')
                    sum_amount += int(result_dic['amount'])  # 합계에 누적

        return sum_amount  # 합계 반환


# env = 'stg'
# date_info = "2023-08-10"
# return functionName, hash, blockNumber, from, to, uuid, amount, fee, createdAt, updatedAt
def get_transaction_delegate(env, user_id, type_):

    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['transactions']
    # address 조회
    address = check_user_address(user_id, env)

    orgsmgr = contract_address(env)[0]
    flux_controller = contract_address(env)[1]

    if type_ == 'App':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'delegate', "to": orgsmgr ,"from":f'{address}'}))

        result = []
        for doc in query_results:
            result_dic = {}
            result_dic['functionName'] = doc.get('functionName')
            result_dic['hash'] = doc.get('hash')
            result_dic['blockNumber'] = doc.get('blockNumber')
            result_dic['from'] = doc.get('from')
            result_dic['to'] = doc.get('to')
            
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'DelegateEvent':
                    params = event_log.get('params', [])
                    result_dic['orgId'] = params[0].get('value')

            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic['amount'] = params[2].get('value')

            result_dic['fee'] = doc.get('fee')
            result_dic['createdAt'] = doc.get('createdAt')
            result_dic['updatedAt'] = doc.get('updatedAt')
            
            result.append(result_dic)
        
        result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)
        
        return result

    elif type_ == 'Flux':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'delegate', "to": flux_controller ,"from":f'{address}'}))
        result = []

        for doc in query_results:
            result_dic = {}
            result_dic['functionName'] = doc.get('functionName')
            result_dic['hash'] = doc.get('hash')
            result_dic['blockNumber'] = doc.get('blockNumber')
            result_dic['from'] = doc.get('from')
            result_dic['to'] = doc.get('to')
            
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'DelegateEvent':
                    params = event_log.get('params', [])
                    result_dic['orgId'] = params[0].get('value')
                    result_dic['amount'] = params[2].get('value')

            result_dic['fee'] = doc.get('fee')
            result_dic['createdAt'] = doc.get('createdAt')
            result_dic['updatedAt'] = doc.get('updatedAt')
            
            result.append(result_dic)
        
        result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)

        return result


# env = 'stg'
# date_info = "2023-08-18"
# return accumulate_delegate
def get_transaction_accumulate_delegate(env, type_):
   
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['transactions']

    sum_amount = 0  # 합계를 저장할 변수

    orgsmgr = contract_address(env)[0]
    flux_controller = contract_address(env)[1]


    if type_ == 'App':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'delegate', "to": orgsmgr}))

        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[2].get('value')
                    sum_amount += int(result_dic['amount'])  # 합계에 누적

        return sum_amount  # 합계 반환

    elif type_ == 'Flux':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'delegate', "to":flux_controller}))

        sum_amount = 0  # 합계를 저장할 변수

        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'DelegateEvent':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[2].get('value')
                    sum_amount += int(result_dic['amount'])  # 합계에 누적

        return sum_amount  # 합계 반환

# env = 'stg'
# date_info = "2023-08-10"
# return functionName, hash, blockNumber, from, to, uuid, amount, fee, createdAt, updatedAt
def get_transaction_claim(env, user_id, type_):
   
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['transactions']
    # address 조회
    address = check_user_address(user_id, env)

    orgsmgr = contract_address(env)[0]
    flux_controller = contract_address(env)[1]


    if type_ == 'App':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'excuteClaimAmount', "to": orgsmgr ,"from":f'{address}'}))

        result = []
        for doc in query_results:
            result_dic = {}
            result_dic['functionName'] = doc.get('functionName')
            result_dic['hash'] = doc.get('hash')
            result_dic['blockNumber'] = doc.get('blockNumber')
            result_dic['from'] = doc.get('from')
            result_dic['to'] = doc.get('to')
            
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'ClaimEvent':
                    params = event_log.get('params', [])
                    result_dic['orgId'] = params[0].get('value')

            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic['amount'] = params[2].get('value')

            result_dic['fee'] = doc.get('fee')
            result_dic['createdAt'] = doc.get('createdAt')
            result_dic['updatedAt'] = doc.get('updatedAt')
            
            result.append(result_dic)
        
        result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)
        
        return result

    elif type_ == 'Flux':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'claim', "to": flux_controller ,"from":f'{address}'}))
        result = []

        for doc in query_results:
            result_dic = {}
            result_dic['functionName'] = doc.get('functionName')
            result_dic['hash'] = doc.get('hash')
            result_dic['blockNumber'] = doc.get('blockNumber')
            result_dic['from'] = doc.get('from')
            result_dic['to'] = doc.get('to')
            
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'ClaimEvent':
                    params = event_log.get('params', [])
                    result_dic['orgId'] = params[0].get('value')
                    result_dic['amount'] = params[2].get('value')

            result_dic['fee'] = doc.get('fee')
            result_dic['createdAt'] = doc.get('createdAt')
            result_dic['updatedAt'] = doc.get('updatedAt')
            
            result.append(result_dic)
        
        result = sorted(result, key=lambda x: x['blockNumber'], reverse=True)

        return result

# env = 'stg'
# date_info = "2023-08-18"
# return accumulate_claim
def get_transaction_accumulate_claim(env, type_):
   
    # 입력한 환경에 따라 mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['transactions']

    sum_amount = 0  # 합계를 저장할 변수

    orgsmgr = contract_address(env)[0]
    flux_controller = contract_address(env)[1]


    if type_ == 'App':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'excuteClaimAmount', "to": orgsmgr}))

        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[2].get('value')
                    sum_amount += int(result_dic['amount'])  # 합계에 누적

        return sum_amount  # 합계 반환

    elif type_ == 'Flux':
        # 쿼리문 실행
        query_results = list(collection.find({"functionName":'claim', "to":flux_controller}))

        claim_sum_amount = 0  # 합계를 저장할 변수
        
        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'ClaimEvent':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[2].get('value')
                    claim_sum_amount += int(result_dic['amount'])  # 합계에 누적

        query_results = list(collection.find({"functionName":'undelegate', "to":flux_controller}))

        undelegate_sum_amount = 0  # 합계를 저장할 변수
        
        for doc in query_results:
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'UnDelegate':
                    params = event_log.get('params', [])
                    result_dic = {}  # for loop 안에서 초기화
                    result_dic['amount'] = params[6].get('value')
                    undelegate_sum_amount += int(result_dic['amount'])  # 합계에 누적

        sum_amount = claim_sum_amount + undelegate_sum_amount

        return sum_amount  # 합계 반환

# env = 'stg'
# date_info = "2023-08-10"
# return _id, txHash, title, content, isExposed, endTxHash, endStatus, createdAt, createdAt, expirationDate
def get_proposal(env, proposal_id):
   
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['proposals']
        
    query_results = list(collection.find({"proposalIdFromContract":str(proposal_id)}))

    result = []
    for doc in query_results:
        result_dic = {}
        result_dic['_id'] = str(doc.get('_id'))
        result_dic['txHash'] = doc.get('txHash')
        result_dic['title'] = doc.get('title')
        result_dic['content'] = doc.get('content')
        result_dic['status'] = doc.get('status')
        result_dic['isExposed'] = doc.get('isExposed')
        result_dic['endTxHash'] = doc.get('endTxHash')
        result_dic['endStatus'] = doc.get('endStatus')
        result_dic['createdAt'] = doc.get('createdAt')
        result_dic['expirationDate'] = doc.get('expirationDate')

        
        result.append(result_dic)
    
    return result


# env = 'stg'
# date_info = "2023-08-10"
# return _id, proposal, soId, userId, address, memberId, votingPower, result, createdAt
def get_voting_histories(env, proposal_id):
   
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    
    # 컬렉션 선택
    proposal_collection = db['proposals']
    proposal_query_results = list(proposal_collection.find({"proposalIdFromContract":str(proposal_id)}))
    for doc in proposal_query_results:
        _id = doc.get('_id')
    
    # 컬렉션 선택
    collection = db['voting_histories']
    query_results = list(collection.find({"proposal":ObjectId(_id)}))

    result = []
    for doc in query_results:
        result_dic = {}
        result_dic['_id'] = str(doc.get('_id'))
        result_dic['proposal'] = str(doc.get('proposal'))
        result_dic['soId'] = doc.get('soId')
        result_dic['userId'] = doc.get('userId')
        result_dic['address'] = doc.get('address')
        result_dic['memberId'] = doc.get('memberId')
        result_dic['votingPower'] = doc.get('votingPower')
        result_dic['result'] = doc.get('result')
        result_dic['createdAt'] = str(doc.get('createdAt'))
        
        result.append(result_dic)

    result = sorted(result, key=lambda x: x['votingPower'], reverse=True)    

    return result

def proposal_date(env, proposal_id):
    
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['proposals']

    query_results = collection.find({'proposalIdFromContract':str(proposal_id)})

    raw_date = query_results[0]['createdAt']
    proposal_date = raw_date.strftime('%Y-%m-%d')

    return proposal_date

def so_voting_power(env, proposal_id):

    sheet_file = "voting_test"
    test_gs = gspread.service_account("")
    so_result_sh = test_gs.open(sheet_file).worksheet("so_result")
    som_result_sh = test_gs.open(sheet_file).worksheet("som_result")

    date_info = proposal_date(env, proposal_id)

    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']

    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['so_snapshots']

    # 쿼리문 실행
    query_results = collection.find({'checkpoint':ObjectId(checkpoint)})

    so_id_li = []
    so_name_li = []
    so_sop_li = []
    so_ratio_li = []
    
    for data in query_results:
        soid = data['soId']
        name = data['name']
        sop = data['sop']
        ratio = data['ratio']

        so_id_li.append(soid)
        so_name_li.append(name)
        so_sop_li.append(sop)
        so_ratio_li.append(ratio)
    
    cell_list = so_result_sh.range('A{}:A{}'.format('2',len(so_id_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = so_id_li[i]
    so_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = so_result_sh.range('B{}:B{}'.format('2',len(so_name_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = so_name_li[i]
    so_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = so_result_sh.range('C{}:C{}'.format('2',len(so_sop_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = str(decimal.Decimal(int(so_sop_li[i])/int(eth)))
    so_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = so_result_sh.range('D{}:D{}'.format('2',len(so_ratio_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = str(decimal.Decimal(int(so_ratio_li[i])/int(eth))*100)
    so_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

def get_vote_list(env, proposal_id):

    sheet_file = "voting_test"
    test_gs = gspread.service_account("")
    so_result_sh = test_gs.open(sheet_file).worksheet("so_result")
    som_result_sh = test_gs.open(sheet_file).worksheet("som_result")

    date_info = proposal_date(env, proposal_id)

    so_voting_power(env, proposal_id)

    checkpoint = get_checkpoints(env, date_info)[0]['checkpoint']
    
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 컬렉션 선택
    collection = db['som_snapshots']

    # 쿼리문 실행
    query_results = collection.find({'checkpoint':ObjectId(checkpoint)})
    som_soid_li = []
    som_address_li = []
    som_sop_eth_li = []
    so_sum_sop = []
    userid_li = []

    # soid별로 sop_eth 합계를 저장할 딕셔너리 초기화
    so_result = {i: 0 for i in range(1, 21)}
    
    for data in query_results:
        soid = data['soId']
        address = data['address']
        sop = data['sop']
        protocol_id = data['protocolId']

        if protocol_id == 1:
            sop_eth = decimal.Decimal(int(sop)/int(eth))

            if sop_eth > 100:
                som_soid_li.append(str(soid))
                som_address_li.append(str(address))
                som_sop_eth_li.append(str(sop_eth))

                # soid 값이 1 ~ 20 사이인 경우 sop_eth 합계에 추가
                if 1 <= soid <= 20:
                    so_result[soid] += sop_eth

    for key, value in so_result.items():
        so_sum_sop.append(value)
    
    # user_id 확인
    # Connect to the database outside the loop
    db = setting.db_connect(env, 'ks_app')
    cursor = db.cursor(pymysql.cursors.DictCursor)

    # Convert the list of addresses into a formatted string for the SQL query
    formatted_addresses = "', '".join(som_address_li)

    # Query to fetch user_ids for the given addresses
    sql_addr = f"SELECT address, user_id FROM kstadium_main.`member` WHERE address IN ('{formatted_addresses}');"
    cursor.execute(sql_addr)
    results = cursor.fetchall()

    # Convert the results into a dictionary with addresses as keys and user_ids as values
    address_to_userid = {result['address']: result['user_id'] for result in results}

    # Initialize an empty list for user_ids
    userid_li = []

    # For each address in som_address_li, fetch the corresponding user_id from the dictionary and append to the list
    for address in som_address_li:
        if address in address_to_userid:
            userid = address_to_userid[address]
            print(userid)
            userid_li.append(userid)
        else:
            print(f"No user_id found for address: {address}")

    cell_list = so_result_sh.range('E{}:E{}'.format('2',len(so_sum_sop)+1))
    for i, cell in enumerate(cell_list):
        cell.value = str(decimal.Decimal(so_sum_sop[i]))
    so_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = som_result_sh.range('A{}:A{}'.format('2',len(som_soid_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = som_soid_li[i]
    som_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = som_result_sh.range('B{}:B{}'.format('2',len(userid_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = userid_li[i]
    som_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = som_result_sh.range('C{}:C{}'.format('2',len(som_address_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = som_address_li[i]
    som_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = som_result_sh.range('D{}:D{}'.format('2',len(som_sop_eth_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = str(decimal.Decimal(som_sop_eth_li[i]))
    som_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    so_soid_col = so_result_sh.col_values(1)[1:]
    so_sop_col = so_result_sh.col_values(5)[1:]
    som_soid_col = som_result_sh.col_values(1)[1:]
    som_sop_col = som_result_sh.col_values(4)[1:]

    time.sleep(5)
    som_voting_power_li = []
    for i in range(0,len(som_soid_col)):
        som_soid = som_soid_col[i]
        som_sop = som_sop_col[i]

        if som_soid in so_soid_col:
            index = so_soid_col.index(som_soid)
            so_sop = so_sop_col[index]
            cal_value = str(round((float(som_sop) / float(so_sop)) * 10000000, 0))
            print(cal_value)

            som_voting_power_li.append(cal_value)

    cell_list = som_result_sh.range('E{}:E{}'.format('2',len(som_voting_power_li)+1))
    for i, cell in enumerate(cell_list):
        cell.value = som_voting_power_li[i]
    som_result_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 


# 2023-10-04 
# wayne
# 기존의 스냅샷 데이터를 삭제하고, 최신 블록을 기준으로 새로운 스냅샷 데이터를 생성합니다.
def snapshot_reset(_env, date_time):
    _env = 'stg'
    sysOS = platform.system()
    if sysOS == "Windows":
        gs = gspread.service_account('')
    elif sysOS == "Linux":
        gs = gspread.service_account('') #참조할 구글시트에 공유 되어있는 json 파일 추가
    elif sysOS == "Darwin":
        gs = gspread.service_account("")
    else:
        pass

    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(_env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']

    checkpoint_id  = get_checkpoints(_env, date_time)[0]['checkpoint']

    collection = db['so_snapshots']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("so_snapshots remove finish")

    collection = db['som_snapshots']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("som_snapshots remove finish")
    
    collection = db['tasks']
    query = {'checkpoint':ObjectId(checkpoint_id), 'name':'snapshot'}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("tasks remove finish")

    cur_block = ex_api_v2.get_block_list(1,1)['blockList'][0]['blockNumber']
    collection = db['checkpoints']
    query = {'_id' : ObjectId(checkpoint_id)}
    update = {'$set' : { 'blockNumber' : cur_block } }
    query_result = collection.update_one(query,update)
    print("blocknumber update finish")
    time.sleep(5)

    result = new_groundchain_api.post_snapshot()

    return result

def reward_reset(checkpoint_id):
    _env = 'stg'
    sheet_file = f"{_env}_reward"
    sysOS = platform.system()
    if sysOS == "Windows":
        gs = gspread.service_account('')
    elif sysOS == "Linux":
        gs = gspread.service_account('') #참조할 구글시트에 공유 되어있는 json 파일 추가
    elif sysOS == "Darwin":
        gs = gspread.service_account("")
    else:
        pass

    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(_env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']

    print(checkpoint_id)

    print("====================== reward 관련 mongoDB 초기화 ======================")
    # 'protocol_fees' 컬렉션 선택
    collection = db['protocol_fees']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("protocol_fees remove finish")

    # 'rewards' 컬렉션 선택
    collection = db['rewards']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("rewards remove finish")

    # 'so_rewards' 컬렉션 선택
    collection = db['so_rewards']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("so_rewards remove finish")

    # 'som_rewards' 컬렉션 선택
    collection = db['som_rewards']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("som_rewards remove finish")

    # 'tasks' 컬렉션 선택
    collection = db['tasks']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("tasks remove finish")

    collection = db['so_snapshots']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("so_snapshots remove finish")

    collection = db['som_snapshots']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("som_snapshots remove finish")

    collection = db['inflations']
    query = {'checkpoint':ObjectId(checkpoint_id)}
    # 데이터 삭제
    query_result = collection.delete_many(query)
    print("inflations remove finish")

    cur_block = ex_api_v2.get_block_list(1,1)['blockList'][0]['blockNumber']
    collection = db['checkpoints']
    query = {'_id' : ObjectId(checkpoint_id)}
    update = {'$set' : { 'blockNumber' : cur_block } }
    query_result = collection.update_one(query,update)
    print("blocknumber update finish")
    time.sleep(5)

    return cur_block

def inflation_check(checkpoint_id):
    _env = 'stg'
    # 입력한 환경에 따라mongoDB 엔드포인트를 가져옴.
    uri = mongo_env(_env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
    # 'rewards' 컬렉션 선택
    collection = db['inflations']
    # 데이터 조회
    query = {'checkpoint':ObjectId(checkpoint_id)}
    query_result = collection.find(query)

    result_li = []
    for doc in query_result:
        result_dic = {}
        result_dic['checkpoint'] = doc['checkpoint']
        result_dic['blockCount'] = doc['blockCount']
        result_dic['blockInflation'] = doc['blockInflation']
        result_dic['transactionCount'] = doc['transactionCount']
        result_dic['rewardFee'] = doc['rewardFee']
        result_dic['soReward'] = doc['soReward']
        result_dic['communityReward'] = doc['communityReward']
        result_dic['devReward'] = doc['devReward']
        result_li.append(result_dic)

    print(result_li)
    so_reward = (result_li[0]['soReward'])

    return so_reward

def reward_recharge(so_reward):
    print("===================== reward_vault 확인 =====================")
    from_wallet = ''
    reward_fee = 602

    # 당일 분배될 리워드 금액
    so_reward = round(int(so_reward)/decimal.Decimal(eth),10)
    print("당일 리워드 분배 금액 : " + str(so_reward))

    # 리워드 분배 vault
    reward_vault = '' 
    before_reward_vault = decimal.Decimal(int(ex_api_v2.get_account_address(reward_vault)['balance'])/decimal.Decimal(eth))
    print("현재 리워드 금고 잔액 : " + str(before_reward_vault))
    print("필요 리워드 금고 잔액 : " + str(so_reward+reward_fee))

    if before_reward_vault >= so_reward + reward_fee:
        print("=============================================================")
        print("현재 잔액으로 리워드 분배가 가능합니다.")

    elif before_reward_vault < so_reward + reward_fee:
        print("=============================================================")
        print("부족한 금액에 대해 송금을 진행합니다.")
        token = ks_api.post_otp_login(from_wallet, '')
        balance = float(ks_api.get_balance(token['accessToken'])['KSTA'])
        print("송금 예정인 금고 잔액 : " + str(balance))

        send_ksta = so_reward + reward_fee - before_reward_vault
        print("송금 예정될 금액 확인 : " + str(send_ksta))

        ks_api.post_sendkok(token['accessToken'], float(send_ksta), reward_vault)

        time.sleep(10)
        after_reward_valut = decimal.Decimal(int(ex_api_v2.get_account_address(reward_vault)['balance'])/decimal.Decimal(eth))
        print("송금 완료후 금고 잔액 : " + str(after_reward_valut))
        print("=============================================================")
        print("리워드 금고 잔액 충전이 완료 되었습니다. 리워드 분배가 가능합니다.")

def reward_excute():
    if  env == 'stg':
        sheet_file = f"{env}_reward"
        sysOS = platform.system()
        if sysOS == "Windows":
            gs = gspread.service_account('')
        elif sysOS == "Linux":
            gs = gspread.service_account('') #참조할 구글시트에 공유 되어있는 json 파일 추가
        elif sysOS == "Darwin":
            gs = gspread.service_account("")
        else:
            print("Unknown operating system.")

        checkpoint_sh = gs.open(sheet_file).worksheet("checkpoint")
        checkpoint_id = ObjectId(checkpoint_sh.get_values("D3")[0][0])
        # mongo reset
        reward_reset(checkpoint_id)

        # inflation 생성
        new_groundchain_api.post_inflation()
        time.sleep(30)
        
        # snapshot 생성 -> 응답 시간 문제로 API 에러 발생하지만, 실제로는 동작됨
        new_groundchain_api.post_snapshot()
        time.sleep(1200)
        
        # reward 생성
        new_groundchain_api.post_reward()
        time.sleep(30)

        so_reward = inflation_check(checkpoint_id)
        time.sleep(30)

        reward_recharge(so_reward)
        time.sleep(30)

        new_groundchain_api.patch_reward()
        time.sleep(30)
    else:
        quit()

def flux_url(id,pw,env):
    ks_api.set_env(env)
    app_login = ks_api.post_otp_login(id,pw,nw=env)
    print(app_login)
    flux_accessKey = ks_api.get_external_accessKey(app_login["accessToken"])
    print(flux_accessKey)
    flux_access_token = ks_api.post_dex_login(flux_accessKey["accessKey"])["accessToken"]    

    if env == 'stg':
        url = ""+flux_accessKey['accessKey']
    elif env == 'prd':
        url = ""+flux_accessKey['accessKey']

    result = []
    result.append(flux_access_token) 
    result.append(url)
    
    return result


def db_so_snapshot(env, date_info):
    
    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
 
    checkpoint_id = ObjectId(get_checkpoints(env, date_info)[0]['checkpoint'])

    # 'so_snapshots' 컬렉션 선택
    collection = db['so_snapshots']
    # 데이터 조회
    # print('ObjectID('+ checkpoint_id +')')
    query = {'checkpoint':checkpoint_id}
    query_result = collection.find(query)

    result_li = []
    for doc in query_result:
        result_dic = {}
        result_dic['soId'] = doc['soId']
        result_dic['name'] = doc['name']
        result_dic['sop'] = doc['sop']
        result_li.append(result_dic)

    return result_li

# checkpoint_id로 오늘날짜 리워드 데이터 확인
def db_so_rewards(env, date_info):

    uri = mongo_env(env)
    # MongoDB 클라이언트 생성
    client = pymongo.MongoClient(uri)
    # 데이터베이스 선택
    db = client['kstadium_main']
 
    checkpoint_id = ObjectId(get_checkpoints(env, date_info)[0]['checkpoint'])
    
    # 'so_rewards' 컬렉션 선택
    collection = db['so_rewards']
    # 데이터 조회
    query = {'checkpoint':checkpoint_id}
    query_result = collection.find(query)

    result_li = []
    for doc in query_result:
        result_dic = {}
        result_dic['soId'] = doc['soId']
        result_dic['reward'] = doc['reward']
        result_li.append(result_dic)

    return result_li

def get_flux_arr(env, date_info):
    so_id_li = db_so_snapshot(env, date_info)
    so_name_li = db_so_snapshot(env, date_info)
    delegate_li = db_so_snapshot(env, date_info)
    reward_li = db_so_rewards(env, date_info)
    arr_li = []
    for i in range(0,len(delegate_li)):
        arr_dic = {}
        so_id_value = str(so_id_li[i]['soId'])
        so_name_value = str(so_name_li[i]['name'])
        reward_value = int(reward_li[i]['reward'])/int(eth)
        delegate_value = int(delegate_li[i]['sop'])/int(eth)
        reward_cal = float(reward_value) * 365
        delegate_cal = float(delegate_value)

        arr = str((reward_cal / delegate_cal) * 100)
        arr_dic['so_id'] = so_id_value
        arr_dic['so_name'] = so_name_value
        arr_dic['rate'] = arr
        arr_li.append(arr_dic)

    # arr_li를 rate 값을 기준으로 내림차순으로 정렬
    arr_li = sorted(arr_li, key=lambda x: float(x['rate']), reverse=True)
    return arr_li

def get_flux_delegator(env):
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT count(id) FROM kstadium_main.som WHERE protocol_id ='2';"
    cursor1.execute(sql)
    rows = cursor1.fetchall()
    count = str(rows[0]['count(id)'])

    return count


def get_flux_total_delegated_amount(env, user_id):

    member_id = get_account_memberid(env, user_id)
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = f"SELECT sum(sop)/1000000000000000000 FROM kstadium_main.som WHERE member_id = {member_id} and protocol_id =2;"
    cursor1.execute(sql)
    rows = cursor1.fetchall()
    sop = str(rows[0]['sum(sop)/1000000000000000000'])

    return sop


def get_flux_total_claimable_ksta(env, user_id):

    member_id = get_account_memberid(env, user_id)
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = f"SELECT sum(claim)/1000000000000000000 FROM kstadium_main.som WHERE member_id = {member_id} and protocol_id =2;"
    cursor1.execute(sql)
    rows = cursor1.fetchall()
    claim = str(rows[0]['sum(claim)/1000000000000000000'])

    return claim


def get_flux_so_list(env):

    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT ranking ,name ,ratio/10000000000000000  FROM kstadium_main.so order by ranking asc;"
    cursor1.execute(sql)
    rows = cursor1.fetchall()

    result_li = []
    for i in range(0, len(rows)):
        result_dic = {}
        result_dic['ranking'] = rows[i]['ranking']
        result_dic['name'] = rows[i]['name']
        result_dic['ratio'] = rows[i]['ratio/10000000000000000']
        result_li.append(result_dic)

    return result_li

def get_rdb_delegate_log(env, user_id, protocol_id):
    
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    id_sql = f"SELECT * FROM kstadium_main.`member` WHERE user_id = '{user_id}';"
    cursor1.execute(id_sql)
    id_rows = cursor1.fetchall()
    id = str(id_rows[0]['id'])

    sql = f"SELECT * FROM kstadium_main.som WHERE member_id = '{id}' and protocol_id = '{protocol_id}' order by so_id asc;"
    cursor1.execute(sql)
    rows = cursor1.fetchall()

    result_li = []
    for i in range(len(rows)):
        result_dic = {}
        result_dic['so_id'] = rows[i]['so_id']
        result_dic['member_id'] = rows[i]['member_id']
        result_dic['protocol_id'] = rows[i]['protocol_id']
        result_dic['sop'] = rows[i]['sop']
        result_dic['claim'] = rows[i]['claim']
        result_dic['created_at'] = rows[i]['created_at']
        result_li.append(result_dic)

    return result_li


# 2023-08-25
# wayne
# return address, id 
def get_account_address(env, user_id):
    
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = f"SELECT * FROM kstadium_main.`member` WHERE user_id = '{user_id}';"
    cursor1.execute(sql)
    id_rows = cursor1.fetchall()

    result_li = []
    result_dic = {}

    result_dic['address'] = str(id_rows[0]['address'])
    result_dic['member_id'] = str(id_rows[0]['id'])
    result_li.append(result_dic)

    return result_li


# 2023-08-25
# wayne
# return user_id, id
def get_account_userid(env, address):
    
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = f"SELECT * FROM kstadium_main.`member` WHERE address = '{address}';"
    cursor1.execute(sql)
    id_rows = cursor1.fetchall()

    result_li = []
    result_dic = {}

    result_dic['user_id'] = str(id_rows[0]['user_id'])
    result_dic['member_id'] = str(id_rows[0]['id'])
    result_li.append(result_dic)

    return result_li

def get_account_memberid(env, user_id):
    
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = f"SELECT id FROM kstadium_main.`member` WHERE user_id = '{user_id}';"
    cursor1.execute(sql)
    id_rows = cursor1.fetchall()

    result_dic = {}

    result_dic['id'] = str(id_rows[0]['id'])

    return result_dic['id']


# 2023-08-23
# wayne
# user_id 입력으로 undelegate 
# 미완성
def get_flux_undelegate(env, user_id):
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    id_sql = f"SELECT * FROM kstadium_main.`member` WHERE user_id = '{user_id}';"
    cursor1.execute(id_sql)
    id_rows = cursor1.fetchall()
    member_id = str(id_rows[0]['id'])
    address = str(id_rows[0]['address'])

    sql = f"SELECT * FROM kstadium_main.som WHERE member_id ='{member_id}'  and protocol_id = 2 and sop > 0 order by so_id ASC ;"
    cursor1.execute(sql)
    rows = cursor1.fetchall()

    soid_li = []
    delegator_address_li = []
    for i in range (0, len(rows)): 
        soid = rows[i]['so_id']
        delegator_address = rows[i]['address']
        soid_li.append(soid)
        delegator_address_li.append(delegator_address)

    token = ks_api.post_otp_login(user_id,"",nw=env)
    flux_accessKey = ks_api.get_external_accessKey(token["accessToken"])
    flux_access_token = ks_api.post_dex_login(flux_accessKey["accessKey"])["accessToken"]  

    result_li = []
    total_result_li = []
    delegated_amount_total = 0
    claimable_amount_total = 0
    my_inksta_amount_total = 0
    for i in range(0, len(soid_li)):
        result_dic = {}
        data = flux_api.get_so_detail(soid_li[i], address)['responseText']
        data_json = json.loads(data)
        soid = data_json['uuid']
        delegated_amount= data_json['delegated_amount']
        claimable_amount = data_json['claimable_reward_by_so']
        my_inksta_amount = data_json['my_inksta']
        
        # 유닉스 타임스탬프 값을 UTC 기준의 datetime 객체로 변환
        claimable_at_utc = datetime.utcfromtimestamp(int(data_json['claimable_at']))
        undelegatable_at_utc = datetime.utcfromtimestamp(int(data_json['undelegatable_at']))

        # UTC+9로 변환
        kst = pytz.timezone('Asia/Seoul')
        claimable_at_kst = claimable_at_utc.replace(tzinfo=pytz.utc).astimezone(kst)
        undelegatable_at_kst = undelegatable_at_utc.replace(tzinfo=pytz.utc).astimezone(kst)

        claimable_at_kst_str = claimable_at_kst.strftime('%Y-%m-%dT%H:%M:%S')
        undelegatable_at_kst_str = undelegatable_at_kst.strftime('%Y-%m-%dT%H:%M:%S')

        claimable_at = claimable_at_kst_str
        undelegatable_at = undelegatable_at_kst_str

        # result_dic 딕셔너리에 값 적재
        result_dic['soid'] = soid
        result_dic['delegated_amount'] = decimal.Decimal(int(delegated_amount)/int(eth))
        result_dic['claimable_amount'] = decimal.Decimal(int(claimable_amount)/int(eth))
        result_dic['my_inksta_amount'] = decimal.Decimal(int(my_inksta_amount)/int(eth))
        result_dic['claimable_at'] = claimable_at
        result_dic['undelegatable_at'] = undelegatable_at

        result_li.append(result_dic)

        delegated_amount_total += (int(delegated_amount)/int(eth))
        my_inksta_amount_total += (int(my_inksta_amount)/int(eth))
        claimable_amount_total += (int(claimable_amount)/int(eth))


    total_result_li.append(delegated_amount_total)
    total_result_li.append(my_inksta_amount_total)
    total_result_li.append(claimable_amount_total)

    undelegate_result_li = []
    for i in range(0, len(soid_li)):
        undelegate_result = flux_api.post_undelegate(flux_access_token, soid_li[i], amount=100000000000000000000)
        undelegate_result_li.append(undelegate_result)

    time.sleep(5)

    return undelegate_result_li


def excute_delegate(env, user_id, start_soid, end_soid, delegate_amount, type_):
    result_li = []

    if env == 'stg':
        so_address = [""]
 
    db = setting.db_connect(env, 'ks_app')
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT id,address  FROM kstadium_main.`member` WHERE user_id = '{}';".format(user_id)
    cursor1.execute(sql)
    rows = cursor1.fetchall()
    try:
        print(user_id)
        member_id = rows[0]['id']
        address = rows[0]['address']

    except IndexError:
        print("존재하지 않는 id 입니다.")
        quit()

    token = ks_api.post_otp_login(user_id,"",nw=env)
    if token["statusCode"] == 200:
        pass
    else:
        print("로그인 실패 했습니다.")

    if type_ == "App":
        for i in range(start_soid, end_soid+1):
            result_dic = {}
            sop_balance = ks_api.get_balance(token["accessToken"])["SOP"] 

            print("> 위임 전 SOP 보유양 :  " + sop_balance + " SOP")

            ksta_balance = float(ks_api.get_balance(token["accessToken"])["KSTA"]) #KSTA

            if float(sop_balance) > float(delegate_amount):
                if ksta_balance < 1:
                    senderid = 'sqeteam2'
                    token_ = ks_api.post_otp_login(senderid,"",nw=env)
                    ks_api.post_sendkok(token_["accessToken"],1,address)
                
                send_delegate_approve = ks_api.post_delegate_approve(token["accessToken"], so_address[int(i)], float(delegate_amount))   
                time.sleep(4)
                send_delegate = ks_api.post_delegate(token["accessToken"], str(i), float(delegate_amount))   
                
                time.sleep(5)
                sop_balance_ = ks_api.get_balance(token["accessToken"])["SOP"]
                cal = float(sop_balance) - float(sop_balance_)
                print("> 위임 후 SOP 보유양 :  " + sop_balance_ + " SOP")
                print("\t{} SO에게 위임한 양 : ".format(i), cal, "SOP")

                result_dic['so_id'] = i
                result_dic['amount'] = cal
                result_dic['message'] = 'Success'

                result_li.append(result_dic)

                time.sleep(5)

            else:
                print("<<<<<<<< 충전 필요 >>>>>>>>")
                if ksta_balance > float(delegate_amount)+11:
                    ks_api.post_sendpool(token["accessToken"], float(delegate_amount))      

                    time.sleep(2)
                    sop_balance = ks_api.get_balance(token["accessToken"])["SOP"] 
                    print("> 충전 후 SOP 보유양 :  " + sop_balance + " SOP")

                    send_delegate_approve = ks_api.post_delegate_approve(token["accessToken"], so_address[int(i)], float(delegate_amount))   
                    time.sleep(3)
                    send_delegate = ks_api.post_delegate(token["accessToken"], str(i), float(delegate_amount))   
                    time.sleep(5)
                    
                    sop_balance_ = ks_api.get_balance(token["accessToken"])["SOP"]
                    cal = float(sop_balance) - float(sop_balance_)
                    print("> 위임 후 SOP 보유양 :  " + sop_balance_)
                    print("\t{} SO에게 위임한 양 : ".format(i), cal, "SOP")

                    result_dic['so_id'] = i
                    result_dic['amount'] = cal
                    result_dic['message'] = 'Success'

                    result_li.append(result_dic)

                    time.sleep(5)

                else:
                    senderid = 'sqeteam2'
                    token_ = ks_api.post_otp_login(senderid,"",nw=env)
                    ks_api.post_sendkok(token_["accessToken"],float(delegate_amount)+11,address)
                    time.sleep(3)

                    ks_api.post_sendpool(token["accessToken"], float(delegate_amount))      
                    time.sleep(3)

                    sop_balance = ks_api.get_balance(token["accessToken"])["SOP"] 
                    print("> 충전 후 SOP 보유양 :  " + sop_balance + " SOP")

                    send_delegate_approve = ks_api.post_delegate_approve(token["accessToken"], so_address[int(i)], float(delegate_amount))   
                    time.sleep(3)
                    send_delegate = ks_api.post_delegate(token["accessToken"], str(i), float(delegate_amount))   
                    time.sleep(3)
                    
                    sop_balance_ = ks_api.get_balance(token["accessToken"])["SOP"]
                    cal = float(sop_balance) - float(sop_balance_)
                    print("> 위임 후 SOP 보유양 :  " + sop_balance_+ " SOP")
                    print("\t{} SO에게 위임한 양 : ".format(i), cal, "SOP")
                
                    result_dic['so_id'] = i
                    result_dic['amount'] = cal
                    result_dic['message'] = 'Success'

                    result_li.append(result_dic)

                    time.sleep(5)

        return result_li


    elif type_ == "Flux":

        flux_accessKey = ks_api.get_external_accessKey(token["accessToken"])
        flux_access_token = ks_api.post_dex_login(flux_accessKey["accessKey"])["accessToken"]    
        wei_delegate_amount = decimal.Decimal(delegate_amount * eth)
        for i in range(start_soid, end_soid+1):
            result_dic = {}
            sop_balance = ks_api.get_balance(token["accessToken"])["SOP"] 

            print("> 위임 전 SOP 보유양 :  " + sop_balance + " SOP")

            ksta_balance = float(ks_api.get_balance(token["accessToken"])["KSTA"]) #KSTA

            if float(sop_balance) > float(delegate_amount):
                if ksta_balance < 1:
                    senderid = 'sqeteam2'
                    token_ = ks_api.post_otp_login(senderid,"",nw=env)
                    ks_api.post_sendkok(token_["accessToken"],1,address)
                
                send_delegate = flux_api.post_delegate(flux_access_token, str(i), wei_delegate_amount)

                time.sleep(5)
                sop_balance_ = ks_api.get_balance(token["accessToken"])["SOP"]
                cal = float(sop_balance) - float(sop_balance_)
                print("> 위임 후 SOP 보유양 :  " + sop_balance_ + " SOP")
                print("\t{} SO에게 위임한 양 : ".format(i), cal, "SOP")

                result_dic['so_id'] = i
                result_dic['amount'] = cal
                result_dic['txhash'] = send_delegate['TxHash']
                result_dic['message'] = 'Success'

                result_li.append(result_dic)

            else:
                print("<<<<<<<< 충전 필요 >>>>>>>>")
                if ksta_balance > float(delegate_amount)+11:
                    print("KSTA는 충분함")
                    ks_api.post_sendpool(token["accessToken"], float(delegate_amount))      

                    time.sleep(2)
                    sop_balance = ks_api.get_balance(token["accessToken"])["SOP"] 
                    print("> 충전 후 SOP 보유양 :  " + sop_balance + " SOP")

                    send_delegate = flux_api.post_delegate(flux_access_token, str(i), wei_delegate_amount)
                    time.sleep(5)
                    
                    sop_balance_ = ks_api.get_balance(token["accessToken"])["SOP"]
                    cal = float(sop_balance) - float(sop_balance_)
                    print("> 위임 후 SOP 보유양 :  " + sop_balance_)
                    print("\t{} SO에게 위임한 양 : ".format(i), cal, "SOP")


                    result_dic['so_id'] = i
                    result_dic['amount'] = cal
                    result_dic['txhash'] = send_delegate['TxHash']
                    result_dic['message'] = 'Success'

                    result_li.append(result_dic)


                else:
                    print("KSTA부터 충전이 필요함.")
                    senderid = 'sqeteam2'
                    token_ = ks_api.post_otp_login(senderid,"",nw=env)
                    ks_api.post_sendkok(token_["accessToken"],float(delegate_amount)+11,address)
                    time.sleep(3)

                    ks_api.post_sendpool(token["accessToken"], float(delegate_amount))      
                    time.sleep(3)

                    sop_balance = ks_api.get_balance(token["accessToken"])["SOP"] 
                    print("> 충전 후 SOP 보유양 :  " + sop_balance + " SOP")

                    send_delegate = flux_api.post_delegate(flux_access_token, str(i), wei_delegate_amount)
                    time.sleep(5)

                    sop_balance_ = ks_api.get_balance(token["accessToken"])["SOP"]
                    cal = float(sop_balance) - float(sop_balance_)
                    print("> 위임 후 SOP 보유양 :  " + sop_balance_+ " SOP")
                    print("\t{} SO에게 위임한 양 : ".format(i), cal, "SOP")
                
                    result_dic['so_id'] = i
                    result_dic['amount'] = cal
                    result_dic['txhash'] = send_delegate['TxHash']
                    result_dic['message'] = 'Success'

                    result_li.append(result_dic)


        return result_li
    


def qa_bot_get_message_ts(slack_channel):
    global get_text
    global channel
    global qa_bot_token
    global request_user
    global permission
    env = 'stg'

    qa_member_list = ['', '', '', '', '']
    qa_bot_token = ''
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    client = WebClient(token=qa_bot_token, ssl=ssl_context)
    channel = slack_channel

    # 슬랙 채널 내 메세지 조회
    conversation_datas = client.conversations_history(channel=channel)

    # 채널 내 메세지 정보 활용을 위해 변수 선언
    messages = conversation_datas.data['messages'][0]
    message = messages['text']
    request_user = messages['user']

    try:
        split_message = message.split(' ')
        get_text = split_message
    except:
        get_text = message
        print("exception 발생,",get_text)

    # Request 유저 권한 판정
    for qa_member in qa_member_list:
        if qa_member in request_user:
            print('request member is QA Member')
            permission = 'qa'
            break
        else:
            permission = 'normal'  

    run(get_text, request_user, permission, env)

def run(get_text, request_user, permission, env):
    call = "<@{}>".format(request_user)
    fail = ""

    ####################################################################################################################################################
    #                                                               Health Check                                                                       #
    ####################################################################################################################################################

    # Health Check - App Condition Check
    if get_text[1] == "app_condition":
        login = ks_api.post_otp_login('qatest','@1234')
        login_result, accesstoken = login['statusCode'], login['accessToken']
        balance_result = ks_api.get_token_balance(accesstoken,"KSTA")['statusCode']
        communitypool_result = ks_api.get_community_balance()['statusCode']

        if login_result != 200 or balance_result != 200 or communitypool_result != 200 :
            print("something is wrong")
            text = "{}\n:red_circle: Test *Failed* :red_circle:\nResult\nlogin result = {}\nbalance result = {}\ncommunity pool = {}".format(call, login_result, balance_result, communitypool_result)
        elif login_result == 200 and balance_result == 200 and communitypool_result == 200:
            print("good")
            text = "{}\nTest Passed, Result\nlogin result = {}\nbalance result = {}\ncommunity pool = {}".format(call, login_result, balance_result, communitypool_result)

    # Health Check - Explorer Condition Check
    elif get_text[1] == "explorer_condition":
        account_info = ex_api_v2.get_account_address('')['statusCode']
        search_address = ex_api_v2.get_search('')['statusCode']
        block_list = ex_api_v2.get_block_list(pageNumber=1,pageSize=10)['statusCode']
        history = ex_api_v2.get_transaction_history()['statusCode']
        token_list = ex_api_v2.get_token_list(pageNumber=1,pageSize=10)['statusCode']

        if account_info != 200 or search_address != 200 or block_list != 200 or history != 200 or token_list != 200:
            print("something is wrong")
            text = "{}\n:red_circle: Test *Failed* :red_circle:\nResult\naccount info = {}\nsearch address = {}\nblock list = {}\nhistory = {}\ntoken list = {}".format(call, account_info, search_address, block_list, history, token_list)
        elif account_info == 200 and search_address == 200 and block_list == 200 and history == 200 and token_list == 200:
            print("everything is good")
            text = "{}\nTest Passed, Result\naccount info = {}\nsearch address = {}\nblock list = {}\nhistory = {}\ntoken list = {}".format(call, account_info, search_address, block_list, history, token_list)
    
    # Health Check - Bridge Condition Check
    elif get_text[1] == "bridge_condition":
        health = br_api.get_health()['statusCode']
        chains = br_api.get_chains()[0]['statusCode']
        transfer_fees = br_api.get_transfer_fees()[0]['statusCode']
        cryptocurruncy = br_api.get_cryptocurrencies()['statusCode']
        history = br_api.get_histories_id('1')['statusCode']

        if health != 200 or chains != 200 or transfer_fees != 200 or cryptocurruncy != 200 or history != 200:
            print("something is wrong")
            text = "{}\n:red_circle: Test *Failed* :red_circle:\nResult\naccount info = {}\nsearch address = {}\nblock list = {}\nhistory = {}\ntoken list = {}".format(call, health, chains, transfer_fees, cryptocurruncy, history)
        elif health == 200 or chains == 200 or transfer_fees == 200 or cryptocurruncy == 200 or history == 200:
            print("everything is good")
            text = "{}\nTest Passed, Result\nbridge_health = {}\nchains = {}\ntransfer_fees = {}\ncryptocurrency = {}\nhistory = {}".format(call, health, chains, transfer_fees, cryptocurruncy, history)



    ####################################################################################################################################################
    #                                                               조회성 기능                                                                           #
    ####################################################################################################################################################

    # 조회성 기능 - User ID / Address
    elif get_text[1] == "get_userinfo":
        text = "{}\n".format(call) + "\n"

        if len(get_text) == 4 or len(get_text) == 5:

            try:
                env = get_text[4]
            except(IndexError):
                env = 'stg'

            if get_text[2] == "id":
                search_user_id = get_text[3]
                request_url = ''.format(env, search_user_id)
                response = requests.get(request_url)
                try:
                    res = json.loads(response.text)
                    text += "User Address = {}\nMember ID = {}".format(res['result'][0]['address'],res['result'][0]['member_id'])
                except Exception as e:
                    print("API 호출 중 오류 발생:", str(e))
                    text += "오류가 발생했습니다. 해당 환경에 존재하지 않는 정보일 수 있습니다."
                    fail = 'fail'

            elif get_text[2] == "address":
                search_user_address = get_text[3]
                request_url = ''.format(env, search_user_address)
                response = requests.get(request_url)
                try:
                    res = json.loads(response.text)
                    text += "User id = {}\nMember ID = {}".format(res['result'][0]['user_id'],res['result'][0]['member_id'])
                except Exception as e:
                    print("API 호출 중 오류 발생:", str(e))
                    text += "오류가 발생했습니다. 해당 환경에 존재하지 않는 정보일 수 있습니다."
                    fail = 'fail'
        else:
            print("입력 값 오류 발생")
            fail = 'fail'
            text += "입력값을 다시 확인해 주세요."

    # 조회성 기능 - Balance
    elif get_text[1] == "get_balance":
        text = "{}\n".format(call) + "\n"

        if len(get_text) == 3:
            id = get_text[2]
            print("{}의 Balance를 조회합니다.".format(id))

            try:
                login = ks_api.post_otp_login(id,"")
                accesstoken = login['accessToken']
            except(KeyError):
                print("DB에 존재하지 않는 ID입니다, KeyError.")
                fail = 'fail'
                text = '{}\n조회에 실패했습니다. (KeyError)'.format(call)

            if login['statusCode'] != 200:
                print("DB에 존재하지 않는 ID입니다, statusCode is not 200")
                fail = 'fail'
                text = '{}\n조회에 실패했습니다. (statusCode is not 200)'.format(call)

            else:
                user_balance = ks_api.get_token_balance(accesstoken)
                if user_balance['statusCode'] != 200:
                    fail = 'fail'
                    text = "Error 발생, {}".format(user_balance['statusCode'])
                else:
                    token_dic = {}
                    for tokens in user_balance['coins']:
                        token_dic[tokens['tokenSymbol']] = tokens['balance']
                text = ""
                text += call +"\n"
                for texts in token_dic.keys():
                    text += f"{texts} : {token_dic[texts]}"+"\n"
        else:
            print("입력 값 오류 발생")
            fail = 'fail'
            text += "입력값을 다시 확인해 주세요."

    # 조회성 기능 - OTP Code
    elif get_text[1] == "otp":
        otp_id = get_text[2]
        try:
            otp_pw = get_text[3]
        except(IndexError):
            otp_pw = ''
        try:
            env = get_text[4]
        except(IndexError):
            env = 'stg'
        request_url = ''.format(otp_id,otp_pw,env)

        try:
            response = requests.get(request_url)
            res = json.loads(response.text)
            text = "{}\nOTP Code : {}\n남은 시간 : {}".format(call, res['otpcode'],res['remaining'])
        except(KeyError):
            fail = "fail"
            text = "{}\nDB에 등록되지 않은 ID 입니다.".format(call)

    # 조회성 기능 - Contract Balance
    elif get_text[1] == "contract_balance":
        text = "{}\n".format(call) + "\n"
        address = get_text[2]
        try:
            blocknubmer = get_text[3]
        except(IndexError):
            blocknubmer = 'Present'
        try:
            env = get_text[4]
        except(IndexError):
            env = 'stg'

        request_url = ''.format(address,blocknubmer,env)

        try:
            response = requests.get(request_url)
            res = json.loads(response.text)
            text += "*Network: {}*\nBlock: {}\nAddress: {}\nValue: {}".format(res['Network'],res['Block'],res['Address'],res['Value'])

        except Exception as e:
            print("API 호출 중 오류 발생:", str(e))
            fail = 'fail'
            text += "API 호출 중 오류 발생"

    # 조회성 기능 - Git Tag
    elif get_text[1] == "git_tags":
        results = {}
        tags = get_tags_v2()
        text = "{}\n".format(call) + "\n"
        fail = 'fail'

        for item in tags:
            repo_name = item["Repository"]
            results[repo_name] = {
                "Latest_PRD_Version": item["Latest_PRD_Version"],
                "DATE_PRD": item["DATE_PRD"],
                "Latest_STG_Version": item["Latest_STG_Version"],
                "DATE_STG": item["DATE_STG"]
            }

        for repo, info in results.items():
            if info['Latest_PRD_Version'] == "" and info['DATE_PRD'] == "" and info['Latest_STG_Version'] == "" and info['DATE_STG'] == "":
                pass
            else:
                text += f"Repository: {repo}" + "\n"
                text += f"Latest PRD Version: {info['Latest_PRD_Version']}" + "\n"
                text += f"DATE PRD: {info['DATE_PRD']}" + "\n"
                text += f"Latest STG Version: {info['Latest_STG_Version']}" + "\n"
                text += f"DATE STG: {info['DATE_STG']}" + "\n"
                text += "-" * 40 + "\n"  # Separating lines for clarity


    ####################################################################################################################################################
    #                                                               전송 기능                                                                            #
    ####################################################################################################################################################

    # 전송 기능 - Send KSTA
    elif get_text[1] == "":
        if permission != "":
            text = "{}\n권한이 없습니다.\nQA 팀에 문의하세요.".format(call)
            fail = "fail"

        elif permission == "":
            user_id = get_text[2]
            amount = get_text[3]
            to_address = check_user_account(user_id)['address']
            result = send_ksta_user(user_id, amount, to_address)
            text = "{}\n".format(call)
            text += "*{}*".format(result['resultMessage'])
            text += "\nBefore Sender Balance = {}".format(result['before_sender_balance'])
            text += "\nBefore Receiver Balance = {}\n".format(result['before_user_balance'])
            text += "\nAfter Sender Balance = {}".format(result['after_sender_balance'])
            text += "\nAfter Receiver Balance = {}".format(result['after_user_balance'])

    # 전송 기능 - Send Token
    elif get_text[1] == "":
        if permission != "":
            text = "{}\n권한이 없습니다.\nQA 팀에 문의하세요.".format(call)
            fail = "fail"

        elif permission == "qa":
            from_id = get_text[2]
            to_id = get_text[5]
            token = get_text[3]
            amount = get_text[4]
            to_address = check_user_account(to_id)['address']
            result = send_token('stg',token,from_id,to_address,amount)
            text = "{}\n".format(call)
            text += "\n*Result Message = {}*".format(result[0])
            text += "\nTx Hash = {}".format(result[1][1])
            text += "\nBefore KSTA Balance = {}".format(result[1][2])
            text += "\nBefore {} Balance = {}".format(token, result[1][4])
            text += "\nAfter KSTA Balance = {}".format(result[1][3])
            text += "\nAfter {} Balance = {}".format(token, result[1][5])



    ####################################################################################################################################################
    #                                                               기타 기능                                                                            #
    ####################################################################################################################################################

    # Help 메시지
    elif get_text[1] == "help":
        text = call+'\n'
        text += '아래 링크를 참조해 주세요.\n\
        '

    # 룰렛 기능
    elif get_text[1] == "룰렛":
        text = call+'\n'
        if len(get_text) == 3:
            input_string = get_text[2]
            fail = "fail"
            text = call+'\n'

            # 입력 문자열을 쉼표로 분할하여 리스트로 변환
            input_string = get_text[2]
            input_list = input_string.split(',')
            
            text_list = []
            
            for item in input_list:
                item = item.strip()
                if item.isnumeric():
                    # 숫자인 경우 숫자 리스트에 추가
                    text_list.append(int(item))
                else:
                    # 숫자가 아닌 경우 리스트에 추가
                    text_list.append(item)
            
            if len(text_list) > 0:
                # 숫자 리스트에서 무작위로 선택
                random_num = random.choice(text_list)
                print("선택된 값: ", random_num)
                text += "결과 : *{}*".format(random_num)
        else:
            print("입력 값 오류 발생")
            fail = 'fail'
            text += "입력값을 다시 확인해 주세요."

    elif get_text[1] == "token_price":
        text = call+'\n'
        fail = 'fail'

        try:
            cex_token = get_text[2]
            network = get_text[3]
        except Exception as e:
            print("입력 값 오류", str(e))
            fail = 'fail'
            text += "입력 값 오류"

        request_url = ''.format(cex_token, network)

        try:
            response = requests.get(request_url)
            res = json.loads(response.text)
            text += "*Network: {}*\nToken: {}\nPrice: {}".format(res['network'],res['token'],res['price'])

        except Exception as e:
            print("API 호출 중 오류 발생:", str(e))
            fail = 'fail'
            text += "API 호출 중 오류 발생, 입력 값을 확인해 주세요."


    # 예외 Case 및 환경 Print Handling
    else:
        print("올바른 명령어가 아닙니다.")
        fail = "fail"
        text = "명령어를 인식하지 못했습니다.\n@QA_Bot help 를 입력 시, 사용 설명서 링크를 받을 수 있습니다."


    if text == '' or text == None:
        text = '결과를 출력하지 못했습니다.\n명령어를 다시 확인해 주세요.\n@QA_Bot help 를 입력 시, 사용 설명서 링크를 받을 수 있습니다.'


    if fail == 'fail' or get_text[1] == "help" or get_text[1] == "contract_balance":
        pass
    else:
        text += "\n\n*Environment = {}*".format(env)

    if get_text[1] == 'otp' and fail == 'fail':
        pass
    elif get_text[1] == 'otp':
        text += "\nOTP Code는 Envrionment가 stg 고정으로 노출됩니다."


    # Slack Message 전송
    requests.post("",
    headers={
        
        "Authorization": "Bearer " + qa_bot_token
        
        },
    data={
        
        "channel":channel,
        "text": f"{text}"
        
        }
    )
