'''
FastAPI 사용해서 Swagger Page 구성에 관련된 내용을 다룹니다.
결과 출력은 아래와 같은 양식으로 작성합니다. 가장 처음에 결과를 보여주고
에러 처리는 resultMessage에 표기합니다.
1. "result": true or false
2. "userID":
3. "resultMessage": "사용자가 존재하지 않습니다."

'''
from typing import Optional
from fastapi import FastAPI, Response, Request, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.openapi.utils import get_openapi
import swagger_func
import os
import json
import time
import asyncio
from collections import OrderedDict
from enum import Enum
import getpass
import datetime
import pymysql
import gzip
import pandas as pd
import zipfile
import decimal

if "LAMBDA_RUNTIME_DIR" in os.environ:
    from mangum import Mangum
else:
     import uvicorn
# import base64

date = datetime.datetime.now()
today = date.strftime("%Y-%m-%d")
eth = 1000000000000000000

class Range(Enum):
    모두 = "모두"
    일부 = "일부"
class Project(Enum):
    모두 = "모두"
    App = "App"
    Flux = "Flux"
class DownloadType(Enum):
    NONE = "none"
    json = "json"
    csv = "csv"
class FunctionType(Enum):
    delegate = "delegate"
    undelegate = "undelegate"
    claim = "claim"
    

######################################
#           환 경 변 수 선 언           #
######################################

def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

def rdb_set(env):
    # DB 접속하기 
# stg
    if env == 'stg':
        endpoint = ''
        stg_myid = ''
        stg_mypasswd = ''
        db = pymysql.connect(host=endpoint, port=3306, user=stg_myid, passwd=stg_mypasswd, db='', charset='utf8')
    #prd
    elif env ==  'prd':
        endpoint = ''
        prd_myid = ''
        prd_mypasswd = ''
        db = pymysql.connect(host=endpoint, port=3306, user=prd_myid, passwd=prd_mypasswd, db='', charset='utf8')
    else:
        print("잘못 입력되었습니다 다시 수행하세요.")
        exit()
    
    return db

stgpw = ''
qapw = ''
last_event_id = None
username = getpass.getuser()

app = FastAPI(
    title="[STG] QA Swagger API",
    description="빠르고 쉽게 사용하기 위해 [STG QA Swagger API]를 운영합니다",
    version="0.1",
    )

def custom_openapi():
    if not app.openapi_schema:
        app.openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            description=app.description,
            terms_of_service=app.terms_of_service,
            contact=app.contact,
            license_info=app.license_info,
            routes=app.routes,
            tags=app.openapi_tags,
            servers=app.servers,
        )
        for _, method_item in app.openapi_schema.get('paths').items():
            for _, param in method_item.items():
                responses = param.get('responses')
                # remove 422 response, also can remove other status code
                if '422' in responses:
                    del responses['422']
    return app.openapi_schema

app.openapi = custom_openapi

# class Item(BaseModel):
#         user_id: str
#         user_pw: str | None = None
#         qa_pw: str | None = None
#         env: str | None = None

# class Message(BaseModel):
#         message: str

######################################
#               O T P                #
######################################
# OTP code, Secret Key 가져오기
# @app.get("/OTP/read/OTPcode", summary="QA DB에 OTP code 확인", 
#          description="QA DB를 조회해서 OTP code를 확인합니다" , tags=['OTP'])
@app.get("/OTP/read/OTPcode", 
         summary="QA DB에 OTP code 확인", 
         description="QA DB를 조회해서 OTP code를 확인합니다", tags=['OTP'],
        #  response_model=Item,
         responses={
            # 404: {"model": Message, "description": "The item was not found"},
            200: {
                "description": "Create OTP code",
                "content": {
                    "application/json": {
                        "example": {"otpcode": "546252", 
                                    "remaining": "27.33 초",
                                    "secretkey": "",
                                    "userID": ""}
                    }
                },
            },
        })
def read_otp_otpcode(user_id: str, pw: str = "medium@1234", env: str = "stg"):
        result = swagger_func.check_user_account(user_id, env)
        if result['result']:
            result = swagger_func.check_user_secretkey(user_id,result['address'],env)
            if result['result']:
                result = swagger_func.get_otpcode(result['secretkey'],user_id,pw,env)
        result['userID'] = user_id
        return result


# STG 사용자 계정을 QA DB에 업데이트
@app.post("/OTP/update/Account", 
          summary="STG 계정 조회 후 QA DB에 ID 및 SecretKey 업데이트", 
         description="STG 사용자 정보를 QA DB에 업데이트 합니다" , tags=['OTP'],
         responses={
            200: {
                "description": "Update QA DB with STG user account",
                "content": {
                    "application/json": {
                        "example": {"resultCode": "Success", 
                                    "resultMessage": "New user creation complete",
                                    "data": {
                                        "user_id":"",
                                        "secret_key":""
                                        }
                                    }
                    }
                },
            },
        })
def update_otp_account(user_id: str, user_pw: str, qa_pw: str):
        if qa_pw == qapw:
            result = swagger_func.add_new_user(user_id, user_pw)
            if result["resultMessage"] == "New user creation complete":
                return result
            else:
                return result
        else:
            return {
                'resultCode': "Failed",
                'resultMessage': "Password incorrected",
                'data': "null"
            }


# QA DB에 OTP Secret Key를 갱신합니다.
@app.post("/OTP/update/SecretKey", summary="QA DB에 OTP Secret Key 갱신", 
          description="STG 사용자 조회 후, 해당 OTP Secretkey 리셋 후 QA DB에 업데이트 합니다" , tags=['OTP'],
          responses={
                200: {
                    "description": "Update OTP Secret Key on QA DB",
                    "content": {
                        "application/json": {
                            "example": {"result": "true", 
                                        "userID": "sqe0a100",
                                        "secretkey": "abcd1234",
                                        "new_secretkey": "qwer1234"}
                                        }
                        }
                    },
                })
def update_otp_secretkey(user_id: str, user_pw: str, qa_pw: str):
        result = {}
        if qa_pw == qapw:
            result = swagger_func.update_secretkey(user_id, user_pw)
        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
        return result


# 시크릿키를 이용한 QR Code 생성
@app.get("/OTP/read/QRcode", summary="시크릿키를 이용한 QR Code 생성", 
         description="시크릿키로 QR Code 생성 후, Google OTP App에 등록해서 사용 할 수 있습니다" , tags=['OTP'],
         responses={
            200: {
                "description": "Create QR-Code to enroll on your google otp",
                "content": {
                    "application/json": {
                        "example": {"result": "QR-CODE"}
                                    }
                    }
                },
             })
def read_otp_qrcode(user_id: str, secret_key: str):
        result = swagger_func.get_qrcode(user_id,secret_key)
        if result['result'] == False:
            return {
                'User ID': user_id,
                'Error Reason': result['message']
            }
        else:
            incoded_image = result['img']
            if "LAMBDA_RUNTIME_DIR" in os.environ:     
                #media_type 을 image/png 설정                               
                response = Response(content=incoded_image, media_type='image/png') 
            else:
                decoded_image = swagger_func.base64.b64decode(incoded_image)
                response = Response(content=decoded_image, media_type='image/jpeg')                        
            return response

######################################
#          Launch Pad                #
######################################
# STG 계정으로 접속 할 수 있는 DEX URL을 제공합니다.
@app.get("/LaunchPad/read/AccessURL", summary="Launch Pad 접속 URL 제공", 
         description="STG 계정으로 접속 할 수 있는 LaunchPad URL을 제공합니다" , tags=['LaunchPad'],
         responses={
            200: {
                "description": "Create URL to access LaunchPad",
                "content": {
                    "application/json": {
                        "example": {"userID": "sqe0a100",
                                    "url": "https://launchpad.stg.kstadium.io/?accessKey=3bdc1c2becc4b516ca09b967c308bca12ddce3d7f941eecc1df6ecbb1043f921"
                                    }
                                    }
                    }
                },
             })
def read_launchPad_accessurl(user_id: str, pw: str = "medium@1234", env: str = "stg"):
        result = {}
        result_temp = swagger_func.check_user_account(user_id, env)
        result['userID'] = user_id
        if result_temp['result']:
            result_temp = swagger_func.launchPad_accesskey(user_id, pw, env)
            result['url'] = result_temp['url']
            return result
        else:
            result['resultMessage'] = result_temp['resultMessage']
            return result

######################################
#               D E X                #
######################################
# DEX Access Token을 가져옵니다.
@app.get("/DEX/read/AccessToken", summary="DEX Access Token 생성", 
         description="사용자 ID로 로그인 후, DEX Access Token을 생성합니다" , tags=['DEX'],
         responses={
            200: {
                "description": "Create Access Token for DEX",
                "content": {
                    "application/json": {
                        "example": {"userID": "sqe0a100",
                                    "address": "0x6cD83Fa1249beF9f2E19308Fca45F452df2b2CeB",
                                    "DEX accessToken": "eyJzdWIiOiJsbG95ZDEwMCIsImluZm8iOnsidXNlcklkIjoibGxveWQxMDAiLCJuYW1lIjoibGxveWQiLCJhY2NvdW50IjoiMHg2Y0Q4M0ZhMTI0OWJlRjlmMkUxOTMwOEZjYTQ1RjQ1MmJmMmIyQ2VCIiwic3ltYm9sIjoiS1NUQSIsImVtYWlsIjoibGxveWQxMDBAeW9wbWFpbC5jb20iLCJsb2dpblRpbWUiOjB9LCJyb2xlcyI6IlJPTEVfREVYIiwiaWF0IjoxNjgxODkxMjE4LCJleHAiOjE2ODE4OTIxMTh9"
                                    }
                                    }
                    }
                },
             })
def read_dex_accesstoken(user_id: str, pw: str = "medium@1234", env: str = "stg"):
        result = {}
        result_temp = swagger_func.check_user_account(user_id, env)
        result['userID'] = user_id
        if result_temp['result']:
            result['address'] = result_temp['address']
            result_temp = swagger_func.dex_accesskey(user_id, pw, env)
            result.update(swagger_func.dex_token(result_temp['accessKey']))
            return result
        else:
            result['resultMessage'] = result_temp['resultMessage']
            return result


# STG 계정으로 접속 할 수 있는 DEX URL을 제공합니다.
@app.get("/DEX/read/AccessURL", summary="DEX 접속 URL 제공", 
         description="STG 계정으로 접속 할 수 있는 DEX URL을 제공합니다" , tags=['DEX'],
         responses={
            200: {
                "description": "Create URL to access DEX",
                "content": {
                    "application/json": {
                        "example": {"userID": "sqe0a100",
                                    "url": "https://stg.atheneswap.io/?accessKey=3bdc1c2becc4b516ca09b967c308bca12ddce3d7f941eecc1df6ecbb1043f921"
                                    }
                                    }
                    }
                },
             })
def read_dex_accessurl(user_id: str, pw: str = "medium@1234", env: str = "stg"):
        result = {}
        result_temp = swagger_func.check_user_account(user_id, env)
        result['userID'] = user_id
        if result_temp['result']:
            result_temp = swagger_func.dex_accesskey(user_id, pw, env)
            result['url'] = result_temp['url']
            return result
        else:
            result['resultMessage'] = result_temp['resultMessage']
            return result


@app.get("/DEX/get/totalsupply_reserve", summary="Total Supply & Reserve 조회", 
        description="Dex Pool의 Total Supply 및 Reserve 양을 조회한다." , tags=['DEX'],
        responses={
            200: {
                "description": "Get Total Supply & Reserve",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Total Supply & Reserve A, B",
                                "result": OrderedDict([
                                        ("KSTA-NST_Total_Supply", "1111.1111"),
                                        ("KSTA-NST_reserve_A", "1111.1111"),
                                        ("KSTA-NST_reserve_B", "1111.1111"),
                                        ("KSTA-inKSTA_Total_Supply", "2222.2222"),
                                        ("KSTA-inKSTA_reserve_A", "2222.2222"),
                                        ("KSTA-inKSTA_reserve_B", "2222.2222"),
                                        ("KSTA-ksUSDT_Total_Supply", "3333.3333"),
                                        ("KSTA-ksUSDT_reserve_A", "3333.3333"),
                                        ("KSTA-ksUSDT_reserve_B", "3333.3333"),
                                        ("KSTA-ksETH_Total_Supply", "4444.4444"),
                                        ("KSTA-ksETH_reserve_A", "4444.4444"),
                                        ("KSTA-ksETH_reserve_B", "4444.4444"),
                                        ("KSTA-LOUI_Total_Supply", "5555.5555"),
                                        ("KSTA-LOUI_reserve_A", "5555.5555"),
                                        ("KSTA-LOUI_reserve_B", "5555.5555"),
                                        ("LOUI-ksUSDT_Total_Supply", "5555.5555"),
                                        ("LOUI-ksUSDT_reserve_A", "5555.5555"),
                                        ("LOUI-ksUSDT_reserve_B", "5555.5555"),
                                        ("LOUI-ksETH_Total_Supply", "5555.5555"),
                                        ("LOUI-ksETH_reserve_A", "5555.5555"),
                                        ("LOUI-ksETH_reserve_B", "5555.5555"),
                                        ("NST-XDC_Total_Supply", "5555.5555"),
                                        ("NST-XDC_reserve_A", "5555.5555"),
                                        ("NST-XDC_reserve_B", "5555.5555"),
                                        ("KSTA-DLT_Total_Supply", "5555.5555"),
                                        ("KSTA-DLT_reserve_A", "5555.5555"),
                                        ("KSTA-DLT_reserve_B", "5555.5555")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )

def get_totalsupply_reserve(env: str):
        result = {}
        result_message = {}
        message, value = swagger_func.get_totalsupply_reserve(env)
        result['result'] = message
        result_message["KSTA-NST_total_supply"] = value[0]
        result_message["KSTA-NST_reserve_a"] = value[1]
        result_message["KSTA-NST_reserve_b"] = value[2]

        result_message["KSTA-inKSTA_total_supply"] = value[3]
        result_message["KSTA-inKSTA_reserve_a"] = value[4]
        result_message["KSTA-inKSTA_reserve_b"] = value[5]

        result_message["KSTA-ksUSDT_total_supply"] = value[6]
        result_message["KSTA-ksUSDT_reserve_a"] = value[7]
        result_message["KSTA-ksUSDT_reserve_b"] = value[8]

        result_message["KSTA-ksETH_total_supply"] = value[9]
        result_message["KSTA-ksETH_reserve_a"] = value[10]
        result_message["KSTA-ksETH_reserve_b"] = value[11]

        result_message["KSTA-LOUI_total_supply"] = value[12]
        result_message["KSTA-LOUI_reserve_a"] = value[13]
        result_message["KSTA-LOUI_reserve_b"] = value[14]

        result_message["LOUI-ksUSDT_total_supply"] = value[15]
        result_message["LOUI-ksUSDT_reserve_a"] = value[16]
        result_message["LOUI-ksUSDT_reserve_b"] = value[17]

        result_message["LOUI-ksETH_total_supply"] = value[18]
        result_message["LOUI-ksETH_reserve_a"] = value[19]
        result_message["LOUI-ksETH_reserve_b"] = value[20]

        result_message["NST-XDC_total_supply"] = value[21]
        result_message["NST-XDC_reserve_a"] = value[22]
        result_message["NST-XDC_reserve_b"] = value[23]

        result_message["KSTA-DLT_total_supply"] = value[24]
        result_message["KSTA-DLT_reserve_a"] = value[25]
        result_message["KSTA-DLT_reserve_b"] = value[26]

        result['resultMessage'] = result_message
        
        return result

@app.get("/DEX/get/swap/estimate", summary="Swap 예상치를 구한다", 
        description="Swap 예상치를 구한다" , tags=['DEX'],
        responses={
            200: {
                "description": "Swap estimate reserveA, reserveB",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("tokenA", "100"),
                                        ("tokenB", "18381.18381")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_swap_estimate(env:str, tokenA: str = Query(..., description="reserveA Token"),tokenB: str = Query(..., description="reserveB Token"),inputToken: str = Query(..., description="Swap에 투입할 Token"),inputAmount:float = Query(..., description="Swap에 투입할 양")):
    result = {}
    value = swagger_func.get_swap_estimate(env, tokenA, tokenB, inputToken, inputAmount)
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result

@app.get("/DEX/get/addLiquidity/estimate", summary="Add Liquidity 예상치를 구한다", 
        description="Add Liquidity 예상치를 구한다" , tags=['DEX'],
        responses={
            200: {
                "description": "Add Liquidity estimate LP Token, reserveA, reserveB",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("lp_token", "230.151"),
                                        ("tokenA", "100.12345"),
                                        ("tokenB", "18381.18381")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_add_liquidity_estimate(env:str, tokenA: str = Query(..., description="reserveA Token"),tokenB: str = Query(..., description="reserveB Token"),inputToken: str = Query(..., description="Liquidity에 투입할 reserveA or reserveB 토큰"),inputAmount:float = Query(..., description="Liquidity에 투입할 reserveA or reserveB Amount")):
    result = {}
    value = swagger_func.get_add_liquidity_estimate(env, tokenA, tokenB, inputToken, inputAmount)
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# get_remove_liquidity_estimate(env, id, pw, tokenA, tokenB, inputToken, inputAmount)
@app.get("/DEX/get/removeLiquidity/estimate", summary="Remove Liquidity 예상치를 구한다", 
        description="Remove Liquidity 예상치를 구한다" , tags=['DEX'],
        responses={
            200: {
                "description": "Remove Liquidity estimate LP Token, reserveA, reserveB",
                "content": {
                    "application/json": {
                            "example": {
                                "Result": "Success",
                                "Message": "check remove LP estimate",
                                "data": OrderedDict([            
                                        ("lp_token", "230.151"),
                                        ("tokenA", "100.12345"),
                                        ("tokenB", "18381.18381")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_remove_liquidity_estimate(env:str, id:str, pw:str, tokenA: str = Query(..., description="reserveA Token"),
                                tokenB: str = Query(..., description="reserveB Token"),
                                inputToken: str = Query(..., description="Liquidity에 제거할 lp or reserveA or reserveB 토큰  \n예) KSTA-LOUI or KSTA or LOUI"),
                                inputAmount:float = Query(..., description="Liquidity에 제거할 lp or reserveA or reserveB Amount")):
    value = swagger_func.get_remove_liquidity_estimate(env, id, pw, tokenA, tokenB, inputToken, inputAmount)
    
    result = value    
        
    return result

@app.get("/DEX/get/Pair/info", summary="Farm의 APR, Total Staked, LP USD 정보 조회", 
        description="Tokenomics 시트 참조 (total_alloc_point, alloc_point, regularRewardperBlock)  \n Tokenomics 폴더 : https://drive.google.com/drive/u/2/folders/1RiUrKOJNRGwKgcW2SeOzf0GgAkDCRNdX" , tags=['DEX'],
        responses={
            200: {
                "description": "Farm의 APR, Total Staked, LP USD 정보 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "Result": "Success",
                                "Message": "check Pair Info",
                                "data": OrderedDict([            
                                        ("total_staked", "23120.151"),
                                        ("apr", "100.12"),
                                        ("lpToken_usd", "18381.18381"),
                                        ("liquidity_usd", "384.4331646")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_pairInfo(env:str, 
                currency:bool = Query(..., description="KSTA로 Pair된 토큰은 True, 토큰으로 구성된 Pair는 False"),
                total_alloc_point: int = Query(..., description="Total Multiplier  \n 예) 30"),
                alloc_point: int = Query(..., description="Multiplier  \n 예) 15"),
                regularRewardperBlock: int = Query(..., description="RegularPool  \n 예) 11600000000"),
                tokenA:str = Query(..., description="reserveA Token"),
                tokenB:str = Query(..., description="reserveB Token")):
    if currency == True:
        value = swagger_func.get_totalStaked_apr(env, total_alloc_point, alloc_point, regularRewardperBlock, tokenA, tokenB)
    else:
        value = swagger_func.get_token_totalStaked_apr(env, total_alloc_point, alloc_point, regularRewardperBlock, tokenA, tokenB)
    
    result = value    
        
    return result

#################################
@app.get("/DEX/get/LP/totalStake", summary="Pool들의 Total Stake 값", 
        description="Pool들의 Total Stake 값" , tags=['DEX'],
        responses={
            200: {
                "description": "Pool들의 Total Stake 값",
                "content": {
                    "application/json": {
                            "example": {
                                "Result": "Success",
                                "Message": "check total staked",
                                "data": OrderedDict([            
                                        ("KSTA-LOUI", "432.151"),
                                        ("KSTA-inKSTA", "1234.151"),
                                        ("KSTA-ksUSDT", "234.151"),
                                        ("KSTA-ksETH", "345.151"),
                                        ("KSTA-NST", "456.151"),
                                        ("LOUI-ksUSDT", "567.151"),
                                        ("LOUI-ksETH", "678.151"),
                                        ("LOUI-singlePool", "890.151")                                        
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_total_staked(env:str
                # tokens:bool = Query("LOUI", "inKSTA", "ksUSDT", "ksETH", "NST", description="KSTA로 Pair된 토큰은 True, 토큰으로 구성된 Pair는 False"),
                # aTokens: int = Query("LOUI", "LOUI", description="Total Multiplier  \n 예) 30"),
                # bTokens: int = Query("ksUSDT", "ksETH", description="Multiplier  \n 예) 15"),
                # single_token: int = Query("LOUI", description="RegularPool  \n 예) 11600000000"),
                ):
    
    tokens = "LOUI", "inKSTA", "ksUSDT", "ksETH", "NST", "DLT"
    currency_total_stake = swagger_func.currency_total_staked(env, tokens)    

    aTokens = "LOUI", "LOUI"
    bTokens = "ksUSDT", "ksETH"
    token_total_stake = swagger_func.token_total_staked(env, aTokens, bTokens)    

    single_token = "LOUI"
    singlePool_total_stake = swagger_func.single_totalStaked(env, single_token)

    data_dic = {}
    result_dic = {}
    for key, val in currency_total_stake.items():
        data_dic[key] = val

    for key, val in token_total_stake.items():
        data_dic[key] = val

    for key, val in singlePool_total_stake.items():
        data_dic[key] = val
    result_dic["Result"] = "Success"
    result_dic["Message"] = "check total staked"
    result_dic["data"] = data_dic

    result = result_dic    
        
    return result

@app.get("/DEX/get/Single/apr", summary="Single Pool의 APR 계산", 
        description="Tokenomics 시트 참조 (total_alloc_point, alloc_point, regularRewardperBlock)  \n" + 
                    "Tokenomics 폴더 : https://drive.google.com/drive/u/2/folders/1RiUrKOJNRGwKgcW2SeOzf0GgAkDCRNdX  \n"+"\n"+
                    "[계산식]  \n"+
                    # yearReward : louiPerblock * (60/comm.BLOCK_TIME_MAP[env.CurrentStage])6024*365
                    # poolWeight : allocPoint / totalSpecialAllocPoint
                    # totalLouiPoolEmissionPerYear : (_yearReward * poolWeight) * 10^18
                    # APR : totalLouiPoolEmissionPerYear / pricePerFullShare / totalShares * 100
                    "yearReward : louiPerblock * (60/comm.BLOCK_TIME_MAP[env.CurrentStage])6024*365  \n"+
                    "poolWeight : allocPoint / totalSpecialAllocPoint  \n"+
                    "totalLouiPoolEmissionPerYear : (_yearReward * poolWeight) * 10^18  \n"+
                    "APR : totalLouiPoolEmissionPerYear / pricePerFullShare / totalShares * 100", tags=['DEX'],
        responses={
            200: {
                "description": "Single Pool의 APR 계산",
                "content": {
                    "application/json": {
                            "example": {
                                "Result": "Success",
                                "Message": "check Single APR",
                                "data": OrderedDict([            
                                        ("apr", "153.02")                                        
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_pairInfo(env:str,                 
                total_alloc_point: int = Query(..., description="Special Pool Total AllocPoint  \n 예) 26400000000"),
                alloc_point: int = Query(..., description="Special Pool AllocPoint  \n 예) 26400000000")):
    
    result_dic = {}    
    value = swagger_func.get_single_apr(env, total_alloc_point, alloc_point)
    try:
        apr = value["apr"]
        result_dic["Result"] = "Success"
        result_dic["Message"] = "check Single APR"
        result_dic["Data"] = value
    except:
        result_dic["Result"] = "Fail"
        result_dic["Message"] = "Fail"
        result_dic["Data"] = {"apr" : "fail"}
    
    result = value    
        
    return result


# get_remove_liquidity_estimate(env, id, pw, tokenA, tokenB, inputToken, inputAmount)
@app.post("/DEX/post/swap", summary="Swap", 
        description="Swap" , tags=['DEX'],
        responses={
            200: {
                "description": "Swap",
                "content": {
                    "application/json": {
                            "example": {
                                "Result": "Success",
                                "message": "Transaction Success",
                                "data": {"Pool" : "KSTA-LOUI",
                                        "txHash" : "0x1af24684a286f3g14gasgargh9m",
                                        "before" : {"reserve" : {"tokenA" : "123.456",
                                                                "tokenB" : "32.181"},
                                                    "balance" : {"tokenA" : "123.456",
                                                                "tokenB" : "32.181"}},
                                        "estimate" : {"tokenA" : "123.456",
                                                    "tokenB" : "32.181"},
                                        "after" : {"reserve" : {"tokenA" : "123.456",
                                                                "tokenB" : "32.181"},
                                                    "balance" : {"tokenA" : "123.456",
                                                                "tokenB" : "32.181"}}}
                                    }
                                    }
                            
                            } 
                }
                }
        )

def post_swap(env:str, id:str, pw:str, tokenA: str = Query(..., description="reserveA Token"),
                                tokenB: str = Query(..., description="reserveB Token"),
                                inputToken: str = Query(..., description="Swap에 투입 할 토큰"),
                                inputAmount:float = Query(..., description="Swap 할 양"),
                                deadline:int = Query(0, description="Expire time, Default=0"),
                                slippage:float = Query(0.5, description="0.5 고정")):
    value = swagger_func.post_swap(env, id, pw, tokenA, tokenB, inputToken, inputAmount, deadline, slippage)
    
    result = value    
        
    return result


######################################
#               C E X                #
######################################
# CEX Token 가격을 가져옵니다.
@app.get("/CEX/get/TokenPrice", summary="CEX Token Price", 
         description="CEX Token 가격을 가져옵니다." , tags=['CEX'],
         responses={
            200: {
                "description": "Get Token Price from CEX",
                "content": {
                    "application/json": {
                        "example": {"Token": "ksta_usdt",
                                    "price_USD": "1",
                                    "price_WON": "1200"
                                    }
                                    }
                    }
                },
             })
def get_token_price(
    token: str = Query("eth_usdt", description="ksta_usdt, KLAY, XRP"),
    network: str = Query("lbank", description="lbank, coinone")
    ):
        result = swagger_func.get_token_price(token, network)
        return result



######################################
#            A C C O U N T           #
######################################
# 사용자 계정 생성
@app.post("/ACCOUNT/create/user", summary="사용자 계정을 생성", 
          description="사용자 조회 후, 없을 경우 해당 계정을 생성합니다.(STG Only)" , tags=['ACCOUNT'],
         responses={
            200: {
                "description": "Create New user on STG",
                "content": {
                    "application/json": {
                        "example": {"result": "true",
                                    "user_id": "sqe0a100",
                                    "resultMessage": "사용자 계정 생성 완료"
                                    }
                                    }
                    }
                },
             })
def create_account_user(user_id: str, qa_pw: str):
        result = {}
        env = 'stg'
        if qa_pw == qapw:
            result = swagger_func.check_user_account(user_id)
            if not result['result']: # STG DB에 사용자 ID가 없을 경우 생성 
                 result = swagger_func.create_user(user_id, stgpw, env)
            else:
                result['result'] = False
                result['resultMessage'] = '{} exists on STG DB'.format(user_id)                
        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
        return result


# user_info
@app.get("/ACCOUNT/get/user_info", summary="사용자 정보 조회", 
        description=
        "## 사용Tip : user_id 또는 address 중 하나를 입력하여 필요한 정보를 조회." , tags=['ACCOUNT'],
        responses={
            200: {
                "description": "user_id 또는 address 입력으로 사용자 계정 정보 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("user_id", "delegate"),
                                        ("address", "0"),        
                                        ("member_id", "0"),        
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_account_user_info(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query('', description="조회할 user_id 입력"),
    address: str = Query('', description="조회할 address 입력")
    ):

    result = {}
    if user_id:
        value = swagger_func.get_account_address(env, user_id)
    elif address:
        value = swagger_func.get_account_userid(env, address)

    result['message'] = "Success"        
    result['result'] = value        
        
    return result

# Admin Access Token
@app.get("/ACCOUNT/get/Accesstoken", 
         summary="Admin Access Token 획득", 
         description="실행시 Admin swagger에서 사용 할 수 있는 Access Token 생성한다", tags=['ACCOUNT'],
         responses={
            200: {
                "description": "Get Admin Access Token",
                "content": {
                    "application/json": {
                        "example": {"result": "true", 
                                    "accesstoken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdXBlcmFkbWluIiwiaW5mbyI6eyJ1c2VySWQiOiJzdXBlcmFkbWluIiwibmFtZSI6InN1cGVyYWRtaW4iLCJhY2NvdW50IjoiU1VQRVIiLCJzeW1ib2wiOm51bGwsImVtYWlsIjpudWxsLCJsb2dpblRpbWUiOjE2OTcwODU3NDIwNDl9LCJyb2xlcyI6IlJPTEVfU1VQRVIiLCJpYXQiOjE2OTcwODU3NDIsImV4cCI6MTY5NzA4OTM0Mn0.uWAoGWTfZ91y-dF37A0K6-xJ7m90E7p636xY1wvx8Zs"
                                    }
                    }
                },
            },
        })
def get_admin_accesstoken(user_id: str = "superadmin", pw: str = "1q2w3e4r!", env: str = "stg"):
        result = swagger_func.get_admin_accesstoken(user_id, pw, env)
        show_result = {}
        show_result['resultMessage'] = result['resultMessage']
        if result['result']:
            show_result['accessToken'] = result['accessToken']
        return show_result


######################################
#        T R A N S A C T I O N       #
######################################
# sqeteam1 계정으로 부터 Send KSTA
@app.post("/TX/send/ksta", summary="KSTA 전송", 
          description="SQETEAM1로부터 KOK을 전송 받는다. Default 1000 KSTA(최대 10,000)" , tags=['Transaction'],
         responses={
            200: {
                "description": "Get the KSTA from [sqeteam0]",
                "content": {
                    "application/json": {
                        "example": {
                            "before_sender_balance": "48662159.657760809072758856",
                            "before_user_balance": "15346.887485125205936989",
                            "after_sender_balance": "48662149.640960809072758856",
                            "after_user_balance": "15356.887485125205936989",
                            "result": "true",
                            "resultMessage": "전송 성공"
                            } }
                    }
                },
             })
def send_ksta(user_id: str, qa_pw: str, amount: float=1000):
        result = {}
        if qa_pw == qapw:
            result = swagger_func.check_user_account(user_id)
            if result['result']: # STG DB에 사용자 확인
                 result = swagger_func.send_ksta_user(user_id, amount, result['address'])
            else:
                result['result'] = False
                result['resultMessage'] = "{} doesn't exist on STG DB".format(user_id)                
        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
        return result

# Send Community Pool
@app.post("/TX/send/communityPool", summary="Community Pool 전송", 
        description="Community Pool로 KSTA를 전송 합니다. (10KSTA 이상)" , tags=['Transaction'],
        responses={
            200: {
                "description": "Send To Community Pool",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Transaction Success",
                                "result": OrderedDict([
                                        ("TxHash", "0xc7d4482fdf6541263ee52f6d0b8eff70245a321ffeabd7547905c2833d365ae1"),
                                        ("Before_CommunityPool_Balance", "1234 KSTA"),
                                        ("Before_KSTA_Balance", "1234 KSTA"),
                                        ("Before_SOP_Balance", "1234 SOP"),
                                        ("After_CommunityPool_Balance", "1234 KSTA"),
                                        ("After_KSTA_Balance", "1234 KSTA"),
                                        ("After_SOP_Balance", "1234 SOP")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def send_community_pool(env: str, user_id: str, qa_pw: str, amount:float):
        result = {}
        result_message = {}
        if qa_pw == qapw:
            message, value = swagger_func.send_communityPool(env, user_id, amount)
            result['result'] = message
            try:
                result_message["TxHash"] = value[0]
                result_message["Before_CommunityPool_Balance"] = value[1]
                result_message["Before_KSTA_Balance"] = value[2]
                result_message["Before_SOP_Balance"] = value[3]
                result_message["After_CommunityPool_Balance"] = value[4]
                result_message["After_KSTA_Balance"] = value[5]
                result_message["After_SOP_Balance"] = value[6]
            except:
                result_message["Message"] = value[0]

            result['resultMessage'] = result_message
        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
        return result


# Send Token
@app.post("/TX/send/token", summary="Token 전송", 
        description="Token을 전송 합니다. " , tags=['Transaction'],
        responses={
            200: {
                "description": "Send To Token",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Transaction Success",
                                "result": OrderedDict([                                        
                                        ("TxHash", "0xc7d4482fdf6541263ee52f6d0b8eff70245a321ffeabd7547905c2833d365ae1"),
                                        ("Before_KSTA_Balance", "1234 KSTA"),
                                        ("Before_NST_Balance", "1234 NST"),                                        
                                        ("After_KSTA_Balance", "1234 KSTA"),
                                        ("After_NST_Balance", "1234 NST")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def send_token(env: str,tokensymbol: str, user_id: str, to_address: str, amount:float, qa_pw: str):
        result = {}
        result_message = {}
        if qa_pw == qapw:
            message, value = swagger_func.send_token(env, tokensymbol, user_id, to_address, amount)
            result['result'] = message            
            
            try:                
                result_message['txHash'] = value[1]                
                result_message['Before_KSTA_Balance'] = value[2]
                result_message[f'Before_{tokensymbol}_Balance'] = value[4]
                result_message['After_KSTA_Balance'] = value[3]
                result_message[f'After_{tokensymbol}_Balance'] = value[5]
            except:
                result_message["Message"] = value[0]

            result['resultMessage'] = result_message

        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
        return result

# Send delegate
@app.post("/TX/send/delegate", summary="Delegate", 
        description="특정 SO에 위임 합니다. " , tags=['Transaction'],
        responses={
            200: {
                "description": "Delegate",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Transaction Success",
                                "result": OrderedDict([            
                                        ("Approve_TxHash", "0xc7d4482fdf6541263ee52f6d0b8eff70245a321ffeabd7547905c2833d365ae1"),                            
                                        ("Transaction_TxHash", "0xc7d4482fdf6541263ee52f6d0b8eff70245a321ffeabd7547905c2833d365ae1"),
                                        ("Before_KSTA_Balance", "1234 KSTA"),
                                        ("Before_SOP_Balance", "1234 SOP"),                                        
                                        ("Before_1_SO_DelegateAmount", "1234 SOP"),            
                                        ("After_KSTA_Balance", "1234 KSTA"),
                                        ("After_SOP_Balance", "1234 SOP"),                                        
                                        ("After_1_SO_DelegateAmount", "1234 SOP")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def send_delegate(env:str, user_id: str, so_number: str, amount:float, qa_pw: str):
        result = {}
        result_message = {}
        if qa_pw == qapw:
            message, value = swagger_func.send_delegate(env, user_id, so_number, amount)
            result['result'] = message
            # result = [approve_txHash, txHash, before_ksta, before_sop, before_delegate_amount, after_ksta, after_sop, after_delegate_amount]
            try:                
                result_message['Approve_TxHash'] = value[0]                
                result_message['Transaction_TxHash'] = value[1]                
                result_message['Before_KSTA_Balance'] = value[2]                
                result_message['Before_SOP_Balance'] = value[3]                
                result_message[f'Before_{so_number}_SO_DelegateAmount'] = value[4]                
                result_message['After_KSTA_Balance'] = value[5]                
                result_message['After_SOP_Balance'] = value[6]                
                result_message[f'After_{so_number}_SO_DelegateAmount'] = value[7]                
            except:
                result_message["Message"] = value[0]

            result['resultMessage'] = result_message
        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
            
        return result

# Send undelegate
@app.post("/TX/send/undelegate", summary="UnDelegate", 
        description="특정(전체) SO에 위임 철회 합니다.  \n 전체 위임 철회 진행 시 사전 Claim 진행" , tags=['Transaction'],
        responses={
            200: {
                "description": "UnDelegate",
                "content": {
                    "application/json": {
                            "example": {
                                "result": "Success",
                                "message": "Undelegate Success",
                                "data": {
                                    "4(SoId)": 
                                    OrderedDict([            
                                        ("undelegate_amount", 12.1242232),                            
                                        ("txHash", "0xc7d4482fdf6541263ee52f6d0b8eff70245a321ffeabd7547905c2833d365ae1"),
                                        ("delegate_amount", 0),
                                        ("claim", 0)
                                    ])
                                }
                                    }
                                    }
                            
                            } 
                }
                }
        )
def send_undelegate(env:str, id:str, password:str, qa_pw:str, so_id:str = Query("", description="공백 입력 시 위임된 전체 SO 위임 전액 Undelegate"), amount:str = Query("", description="공백 시 해당 SO 전액 위임 철회")):
        result = {}        
        if qa_pw == qapw:
            result_dic, message_dic, result_data_dic = swagger_func.send_undelegate(env, id, password, so_id, amount)            
            
            result["result"] = result_dic["result"]
            result["message"] = message_dic["message"]
            result["data"] = result_data_dic["data"]

        else:
            result['result'] = False
            result['message'] = 'QA Password incorrected'
            
        return result

##################
# Send claim
@app.post("/TX/send/claim", summary="Claim", 
        description="전체 또는 특정 SO Claim 합니다. " , tags=['Transaction'],
        responses={
            200: {
                "description": "Claim",
                "content": {
                    "application/json": {
                            "example": {
                                "result": "Pass",
                                "message": "claim success",
                                "total_claimAmount":1422.1765997574175,
                                "data" : {'1': OrderedDict([            
                                        ("balance", 631.9508795015548),                            
                                        ("transaction_result", "success"),
                                        ("txHash", "0xee882a8736b470b0fa61df280f5b00a7b01c78d957efe275c6af80fe81ab1e2b")
                                    ])
                                    }
                                    }
                                    }
                            
                            } 
                }
                }
        )
def send_claim(env:str, qa_pw :str, id:str, pw:str, type:str=Query("", description="all or 공백"), orgId:str=Query("", description="1 (type을 공백으로 적용 시 claim 받을 SOID 기입)")):
        result = {}        
        if qa_pw == qapw:
            result_dic, message_dic, data_dic = swagger_func.send_claim(env, id, pw, type, orgId)  
            result['result'] = result_dic['result']
            result['resultMessage'] = message_dic['message']
            try:
                result['total_claimAmount'] = data_dic["total_claimAmount"]
            except(KeyError):
                pass
            result['data'] = data_dic['data']
        else:
            result['result'] = False
            result['resultMessage'] = 'QA Password incorrected'
            
        return result


# TX hash, Address, Contract, Block number를 이용해서 Transaction을 상세히 검토할 수 있다.
@app.get("/TX/read/txDecoder", summary="Tx Hash 및 Block 값으로 해당 Address의 정보 조회", 
         description="TX hash, Address, Contract, Block number를 이용해서 Transaction을 상세히 검토할 수 있다" , tags=['Transaction'])
def read_tx_decoder(tx_hash: str, address: str, contract: str, block: str):
        result = {}


######################################
#          SMART CONTRACTS           #
######################################
if "LAMBDA_RUNTIME_DIR" not in os.environ:
    # 스마트컨트랙트에 특정 address 자산 조회
    @app.get("/SC/get/coin", summary="스마트컨트랙트 코인 자산 조회", 
            description="스마트컨트랙트에 특정 address 자산 조회" , tags=['SmartContract'],
            responses={
                200: {
                    "description": "Get the Vault assert",
                    "content": {
                        "application/json": {
                            "example": {
                                "Network": "stg",
                                "Block": "34028108",
                                "Address": "0xBc43e890A0cb0b3Bce2251E7d649E846BcC201b4",
                                "Value": "999999.5293192"
                                } }
                        }
                    },
                })
    def get_assert(addr: str, blocknum: str = "Present", env: str = "stg"):
            result = {}
            result = swagger_func.sc_get_assert(addr,blocknum,env)            
            return result
    
    # 스마트컨트랙트에 특정 address Token 자산 조회
    @app.get("/SC/get/Token", summary="스마트컨트랙트 토큰 자산 조회", 
            description="스마트컨트랙트에 특정 address 토큰 자산 조회" , tags=['SmartContract'],
            responses={
                200: {
                    "description": "Get the Token assert",
                    "content": {
                        "application/json": {
                            "example": {
                                "Network": "stg",
                                "Token" : "NST",
                                "Block": "34028108",
                                "Address": "0xBc43e890A0cb0b3Bce2251E7d649E846BcC201b4",
                                "Value": "999999.5293192"
                                } }
                        }
                    },
                })
    def get_token_assert(addr: str, blocknum: str = "", env: str = "stg", token_symbol: str = Query(..., description="Token Symbol : SOP, NST, WKSTA, LOUI, KSUSDT, KSKOK, KSETH, inKSTA, XDC, DLT, WKSTA_NST, WKSTA_LOUI, WKSTA_KSUSDT, WKSTA_KSKOK, WKSTA_KSETH, WKSTA_inKSTA, LOUI_KSUSDT, LOUI_KSETH, NST_XDC, WKSTA_DLT")):
            result = {}
            result = swagger_func.sc_get_token_asset(token_symbol,addr,blocknum,env)            
            return result

    # 스마트컨트랙트에 특정 address Token 자산 조회
    @app.get("/SC/get/DelegateInfo", summary="스마트컨트랙트 위임양 & 리워드양 자산 조회", 
            description="스마트컨트랙트에 특정 address 위임양 & 리워드양 자산 조회" , tags=['SmartContract'],
            responses={
                200: {
                    "description": "Get the Delegate & Claim assert",
                    "content": {
                        "application/json": {
                            "example": {
                                "Network": "stg",
                                "Address": "0xBc43e890A0cb0b3Bce2251E7d649E846BcC201b4",
                                "value": "[{'soId:1', 'DelegateAmount:123.123', 'ClaimAmount:111.151'}...]"
                                } }
                        }
                    },
                })
    def get_delegate_claim_assert(addr: str, blocknum: str = "", env: str = "stg"):
            result_dic = {}
            result = swagger_func.sc_get_delegate_claim_asset(addr,blocknum,env) 
            result_dic["Network"] = env
            result_dic["Address"] = addr
            if blocknum != "":
                result_dic["blockNumber"] = blocknum
            result_dic["value"] = result

            return result_dic
    
    # 스마트컨트랙트에 특정 address flux 위임 자산 조회
    @app.get("/SC/get/flux/DelegateInfo", summary="스마트컨트랙트 Flux 위임양 & 리워드양 자산 조회", 
            description="스마트컨트랙트에 특정 address Flux 위임양 & 리워드양 자산 조회" , tags=['SmartContract'],
            responses={
                200: {
                    "description": "Get the Flux Delegate & Claim assert",
                    "content": {
                        "application/json": {
                            "example": {
                                "Network": "stg",
                                "Address": "0xBc43e890A0cb0b3Bce2251E7d649E846BcC201b4",
                                "value": "[{'soId:1', 'DelegateAmount:123.123', 'ClaimAmount:111.151'}...]"
                                } }
                        }
                    },
                })
    def get_flux_delegate_claim_assert(addr: str, blocknum: str = "", env: str = "stg"):
            result_dic = {}
            so_li, add_li = swagger_func.get_flux_address(env, addr)
            result = swagger_func.sc_get_flux_delegate_claim_asset(so_li,add_li,blocknum,env)            
            result_dic["Network"] = env
            result_dic["Address"] = addr
            if blocknum != "":
                result_dic["blockNumber"] = blocknum
            result_dic["value"] = result

            return result_dic
    
    # 스마트컨트랙트에 SO Total Delegate 조회
    @app.get("/SC/get/so/totalDelegate", summary="스마트컨트랙트 SO Total Delegate (OrgsMgr)", 
            description="스마트컨트랙트에 SO Leader Total Delegate 조회" , tags=['SmartContract'],
            responses={
                200: {
                    "description": "Get the SO Total Delegate",
                    "content": {
                        "application/json": {
                            "example": {
                                "Network": "stg",
                                "blockNumber":"13123",
                                "value": "[{'soId:1', 'totalDelegate:123.123'}...]"
                                } }
                        }
                    },
                })
    def sc_get_so_total_delegate(blocknum: str = "", env: str = "stg"):
        result_dic = {}
        result = swagger_func.sc_get_so_total_delegate(blocknum,env) 
        result_dic["Network"] = env            
        if blocknum != "":
            result_dic["blockNumber"] = blocknum
        result_dic["value"] = result

        return result_dic
    
######################################
#               EXPLORER             #
######################################

@app.get("/Explorer/get/blockNumber", summary="날짜, 시간으로 BlockNumber 구하기", 
        description="특정 날짜, 시간으로 Block Number 구하기 " , tags=['Explorer'],
        responses={
            200: {
                "description": "Block Number 확인",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("date", "2023-07-18"),
                                        ("time", "18:00:00"),                         
                                        ("blockNumber", "3121235")

                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_findBlock(env: str ="stg", date: str = Query(None, description="예) 2023-07-18, 미 입력시 현재 날짜 적용"),time: str = Query(None, description="예) 12:00:00, 미 입력시 현재 시간 적용")):
    result = {}
    value = swagger_func.get_findBlock(env, date, time)
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result



######################################
#            B R I D G E             #
######################################

# get Bridge info
@app.get("/Bridge/get/withdrawn", summary="브릿지 자산이동 조회", 
        description="특정 Address의 자산이동 조회. " , tags=['Bridge'],
        responses={
            200: {
                "description": "브릿지 자산이동 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("update_at", "2023-07-10"),                            
                                        ("token_symbol", "KSTA"),
                                        ("tx_hash", "0x4cc3e01d221396ce74168ec14cddfb0d5a6dcac6644b01f3c5f3819c22de2ffd"),
                                        ("sender", "0xe4edda1485110e6dacce0c68c9b4f62e58eb0b0d"),                                        
                                        ("receiver", "0xe4edda1485110e6dacce0c68c9b4f62e58eb0b0d"),            
                                        ("block_number", "33333"),
                                        ("amount", "1234"),                                        
                                        ("before_balance", "1234"),
                                        ("after_balance", "1234")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
# str = Query(..., description="Token")
def get_bridge_info(address: str, count: str = "", from_chain: str = Query(..., description="ETH or GND"), token_symbol: str = Query(..., description="ALL, KSTA, ETH, USDT"),   date: str= Query(None, description="2023-07-12"), env: str = "stg"): #env, asset, address, date_
    result = {}
    value = swagger_func.get_data(count, env, token_symbol, from_chain, address, date)
    result['message'] = "Success"        

    result['result'] = value        
        
    return result


######################################
#        SLACK JIRA INTERGRATION     #
######################################

@app.post("/QA/post/qa_bot", summary="QA Bot",
        description="멘션한 채널에 입력받은 명령어의 실행 결과를 공유합니다.",  tags=['QA Bot'],
        responses={
        200: {
                "description": "null",
                "content": {
                    "application/json": {
                            "example": {
                                    }
                                    }
                            
                            } 
                }
                }
        )
async def qa_bot(request:Request):
    event_data = await request.json()
    if event_data['type'] == 'url_verification':
        challenge = event_data['challenge']
        return challenge
    if not request.headers.get('x-slack-retry-num') and (event := event_data.get('event')):
        try:
            if "event" in event_data:
                # 이벤트 처리
                print("request channel =",event_data['event']['channel'])
                print("request command =",event_data['event']['text'])
                print("request user =",event_data['event']['user'])
                slack_channel = event_data['event']['channel']
                swagger_func.qa_bot_get_message_ts(slack_channel)
                message = "Success"
                headers = {"X-Slack-No-Retry": "1"}
            return Response(content=message, headers=headers)
        except(KeyError):
            print("KeyError")
            pass


@app.post("/JIRA/send/issue", summary="CS 내용 JIRA에 등록", 
          description="SLACK으로 전달받은 내용 JIRA에 등록" , tags=['CS'],
         responses={
            200: {
                "description": "POST JIRA CS Issue",
                "content": {
                    "application/json": {
                        "example": {
                            "project": {"key": "MCBT"},
                            "summary": "CS Title",
                            "description": "CS Descrioption",
                            "issuetype": {"name": "CS"},
                            "priority": {"name": "High"},
                            "assignee": {"name": "Unassigned"},
                            "Components": "장애"                            
                            } }
                    }
                },
             })

async def post_cs_issue(request:Request):  
    global last_event_id  
    event_data = await request.json()     
    # payload = await request.json()
    if not request.headers.get('x-slack-retry-num') and (event := event_data.get('event')):
        try:
            if "challenge" in event_data:
                # URL 확인 이벤트 처리
                return event_data
            elif "event" in event_data:
                # 이벤트 처리                            
                event_id = event_data.get("event_id")

                if event_id == last_event_id:
                    pass
                else:
                    last_event_id = event_id
                    # await asyncio.sleep(5)
                    result = swagger_func.handle_slackEvent(event_data)
                    message = "Success"
                    headers = {"X-Slack-No-Retry": "1"}
                    return Response(content=message, headers=headers)                  
        except(KeyError):
            pass
        # Your logic
    return event_data


######################################
#                Q A                 #
######################################

# qa prd wallet balance check
@app.get("/QA/get/balance", summary="QA PRD Wallet test 전, 후 자산 조회", 
        description="QA PRD Wallet test 전, 후 자산 조회 " , tags=['QA'],
        responses={
            200: {
                "description": "QA PRD TEST Wallet 자산 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": {"before" : OrderedDict([            
                                        ("ETH_blockNumber", "313133"),                            
                                        ("ETH_KSTA", "123.123"),
                                        ("ETH_USDT", "23.121"),
                                        ("ETH_ETH", "0.1215"),                                        
                                        ("GND_blockNumber", "13135153"),            
                                        ("GND_KSTA", "1111.151"),
                                        ("GND_ksUSDT", "262.5153"),                                        
                                        ("GND_ksETH", "1.15381")                                        
                                    ])
                                    , "after" : OrderedDict([            
                                        ("ETH_blockNumber", "313133"),                            
                                        ("ETH_KSTA", "123.123"),
                                        ("ETH_USDT", "23.121"),
                                        ("ETH_ETH", "0.1215"),                                        
                                        ("GND_blockNumber", "13135153"),            
                                        ("GND_KSTA", "1111.151"),
                                        ("GND_ksUSDT", "262.5153"),                                        
                                        ("GND_ksETH", "1.15381")                                        
                                    ])
                                    }
                                    }
                                    }
                            
                            } 
                }
                }
        )

def get_testWallet_balance(date: str = Query(..., description="2023-07-19"),startTime: str = Query(..., description="10:00:00"),endTime: str = Query(..., description="12:00:00")): #env, asset, address, date_
    result = {}
    value = swagger_func.get_eth_gnd_balance(date, startTime, endTime)
    result['message'] = "Success"        
    result['result'] = value        
        
    return result

@app.get("/QA/get/ethreum/balance", summary="Metamask 지갑 주소로 Balance 조회 (PRD)", 
        description="Metamask 지갑 주소로 Balance 조회" , tags=['QA'],
        responses={
            200: {
                "description": "Metamask 지갑 주소로 Balance 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("blockNumber", "17542544"),
                                        ("KSTA", "18381.18381"),                         
                                        ("USDT", "142.1515"),
                                        ("ETH", "0.12345")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_ethreum_balance(etherium_address: str = Query(..., description="Metamask 지갑 주소"),blockNumber: int = Query(None, description="Ethscan Block Number")):
    result = {}
    value = swagger_func.get_ethreum_balance(etherium_address, blockNumber)
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result

    
@app.get("/QA/get/google/sheetKey", summary="QA에서 사용하는 Google SheetKey 다운로드", 
        description="QA에서 사용하는 Google SheetKey를 Zip 파일로 다운로드  \n/Users/medium/autotest/google 경로에 저장 후 사용" , tags=['QA'],
        responses={
            200: {
                "description": "QA에서 사용하는 Google SheetKey 다운로드",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("data", "sheetKey.zip"),
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )

def get_google_sheetKey():

    zip_name, zip_path = swagger_func.get_google_sheetKey()
    response = FileResponse(zip_path, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zip_name}"})

    return response

from pydantic import BaseModel
from typing import List
class Item(BaseModel):
    Repository: str
    Latest_PRD_Version: str
    DATE_PRD: str
    Latest_STG_Version: str
    DATE_STG: str

@app.get("/QA/get/repositories/tags", summary="Crypted [PRD, STG] 배포 SW version", 
        description="Git Tag 정보를 활용한 PRD, STG 배포 SW 확인  \n실행 시간 약 1분" , tags=['QA'],
        response_model=List[Item]
        )

def get_repositories_tags(): 
    return swagger_func.get_tags()


######################################
#                MONGO               #
######################################
# checkpoint
@app.get("/Mongo/get/checkpoints", summary="checkpoint 조회", 
        description="date 입력으로 checkpoints 값 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 date_info 기준, mongoDB의 checkpoints 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("checkpoint", "64b95a6b83fa5faf549622dc"),
                                        ("blockNumber", "0"),                         
                                        ("createdAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_checkpoints(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24")
    ):
    
    result = {}
    value = swagger_func.get_checkpoints(env, date_info)
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result

# inflation
@app.get("/Mongo/get/inflations", summary="inflations 조회", 
        description="date 입력으로 inflations 값 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 date_info 기준, mongoDB의 inflations 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("checkpoint", "64b95a6b83fa5faf549622dc"),
                                        ("blockCount", "0"),        
                                        ("blockInflation", "0"),        
                                        ("transactionCount", "0"),        
                                        ("fee", "0"),        
                                        ("soReward", "0"),        
                                        ("communityReward", "0"),     
                                        ("devReward", "0"),                         
                                        ("createdAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_inflations(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24"),
    ):
    
    result = {}
    value = swagger_func.get_inflations(env, date_info)
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result

# so_snapshot
@app.get("/Mongo/get/so_snapshots", summary="so_snapshot 조회", 
        description="date 입력으로 so_snapshots 값 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 date_info 기준, mongoDB의 snapshots 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("checkpoint", "64b95a6b83fa5faf549622dc"),
                                        ("soId", "so_id"),        
                                        ("name", "so_name"),        
                                        ("ranking", "0"),        
                                        ("sop", "0"),        
                                        ("ratio", "0"),        
                                        ("claim", "0"),     
                                        ("contract", "0xbEB45E08155B8312eCC7CD44380a4912F0d3849D"),
                                        ("leader", "0xbEB45E08155B8312eCC7CD44380a4912F0d3849D"),  
                                        ("createdAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_so_snapshots(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24"),
    range: Range = Query(Range.모두, description="전체 SO 검색 -> 모두  \n특정 SO 검색 -> 일부"),
    so_id: Optional[int] = Query(None, description="조회할 so_id를 입력하세요.")
    ):

    result = {}
    if range == Range.모두:
        value = swagger_func.get_so_snapshots(env, date_info)
    else:  #
        value_ = swagger_func.get_so_snapshots(env, date_info)
        value = value_[so_id-1]

    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# som_snapshot
@app.get("/Mongo/get/som_snapshots", summary="som_snapshot 조회", 
        description="date 입력으로 som_snapshots 값 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 date_info 기준, mongoDB의 snapshots 조회",
                "content": {
                    "application/jsomn": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("checkpoint", "64b95a6b83fa5faf549622dc"),
                                        ("soId", "1"),        
                                        ("memberId", "1"),        
                                        ("protocolId", "1"),        
                                        ("address", "0xe68F32846F1CB1E924aB3E320028154451D68049"),        
                                        ("sop", "0"),        
                                        ("ratio", "0"),     
                                        ("claim", "0"),                         
                                        ("createdAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_som_snapshots(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24"),
    project: Project = Query(Project.모두, description="전체 프로젝트 검색 -> 모두  \nApp에서만 검색    -> App  \nFlux에서만 검색    -> Flux"),
    range: Range = Query(Range.모두, description="전체 유저 검색 -> 모두  \n 특정 유저 검색 -> 일부"),
    user_id: Optional[str] = Query(None, description="조회할 user_id를 입력하세요."),
    download_type: DownloadType = Query(DownloadType.NONE, description="range값이 모두일 경우 json or csv 선택")
    ):

    result = {}
    if range == Range.모두:
        if project == Project.모두:
            data = swagger_func.get_som_snapshots(env, date_info)
            if download_type == DownloadType.json:
                filename = "data.json.gz"            
                with gzip.open(filename, "wb") as f:
                    json_data = json.dumps(data).encode("utf-8")
                    f.write(json_data)

                response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

                return response
            
            elif download_type == DownloadType.csv:
                zipname = "data.csv.gz" 
                filename = "data.csv" 

                json_data = json.dumps(data)                 
                data = pd.read_json(json_data)

                # CSV 파일로 변환하여 저장
                data.to_csv(filename, index=False)

                with zipfile.ZipFile(zipname, 'w') as zipf:
                    zipf.write(filename, os.path.basename(filename))                

                response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

                return response

        elif project == Project.App:
            values = swagger_func.get_som_snapshots(env, date_info)
            data = [item for item in values if item.get('protocolId') == 1]

            if download_type == DownloadType.json:
                filename = "data.json.gz"            
                with gzip.open(filename, "wb") as f:
                    json_data = json.dumps(data).encode("utf-8")
                    f.write(json_data)

                response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

                return response
            
            elif download_type == DownloadType.csv:
                zipname = "data.csv.gz" 
                filename = "data.csv" 

                json_data = json.dumps(data)                 
                data = pd.read_json(json_data)

                # CSV 파일로 변환하여 저장
                data.to_csv(filename, index=False)

                with zipfile.ZipFile(zipname, 'w') as zipf:
                    zipf.write(filename, os.path.basename(filename))                

                response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

                return response

        elif project == Project.Flux:
            values = swagger_func.get_som_snapshots(env, date_info)
            data = [item for item in values if item.get('protocolId') == 2]
            if download_type == DownloadType.json:
                filename = "data.json.gz"            
                with gzip.open(filename, "wb") as f:
                    json_data = json.dumps(data).encode("utf-8")
                    f.write(json_data)

                response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

                return response
            
            elif download_type == DownloadType.csv:
                zipname = "data.csv.gz" 
                filename = "data.csv" 

                json_data = json.dumps(data)                 
                data = pd.read_json(json_data)

                # CSV 파일로 변환하여 저장
                data.to_csv(filename, index=False)

                with zipfile.ZipFile(zipname, 'w') as zipf:
                    zipf.write(filename, os.path.basename(filename))                

                response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

                return response

    elif range == Range.일부:
        db = rdb_set(env)
        cursor1 = db.cursor(pymysql.cursors.DictCursor)
        sql = f"SELECT id FROM kstadium_main.`member` WHERE user_id = '{user_id}';"
        cursor1.execute(sql)
        rows = cursor1.fetchall()
        memberid = rows[0]['id']

        if project == Project.모두:
            values = swagger_func.get_som_snapshots(env, date_info)
            value = [item for item in values if item.get('memberId') == memberid]
            # with open(f'/Users/{username}/Downloads/{str(date_info+address)+"+모두(APP+FLUX)"}.json', 'w') as f:
            #     json.dump(values, f, default = myconverter)
            # value = f'/Users/{username}/Downloads/{str(date_info+address)+"+모두(APP+FLUX)"}.json' + " 파일을 확인하세요."

        elif project == Project.App:
            values = swagger_func.get_som_snapshots(env, date_info)
            value = [item for item in values if item.get('memberId') == memberid and item.get('protocolId') == 1]
            # with open(f'/Users/{username}/Downloads/{str(date_info+address)+"+APP"}.json', 'w') as f:
            #     json.dump(values, f, default = myconverter)
            # value = f'/Users/{username}/Downloads/{str(date_info+address)+"+APP"}.json' + " 파일을 확인하세요."

        elif project == Project.Flux:
            values = swagger_func.get_som_snapshots(env, date_info)
            value = [item for item in values if item.get('memberId') == memberid and item.get('protocolId') == 2]
            # with open(f'/Users/{username}/Downloads/{str(date_info+address)+"+FLUX)"}.json', 'w') as f:
            #     json.dump(values, f, default = myconverter)
            # value = f'/Users/{username}/Downloads/{str(date_info+address)+"+FLUX)"}.json' + " 파일을 확인하세요."

    result['message'] = "Success"   
    result['result'] = value        
        
    return result


# so_reward
@app.get("/Mongo/get/so_rewards", summary="so_reward 조회", 
        description="date 입력으로 so_rewards 값 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 date_info 기준, mongoDB의 rewards 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("checkpoint", "64b95a6b83fa5faf549622dc"),
                                        ("soId", "1"),        
                                        ("reward", "0"),        
                                        ("basicReward", "0"),        
                                        ("blockReward", "0"),        
                                        ("rankReward", "0"),        
                                        ("leaderReward", "0"),     
                                        ("memberReward", "0"),                         
                                        ("createdAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_so_rewards(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24"),
    range: Range = Query(Range.모두, description="전체 SO 검색 -> 모두  \n특정 SO 검색 -> 일부"),
    so_id: Optional[int] = Query(None, description="조회할 so_id를 입력하세요.")
    ):

    result = {}
    if range == Range.모두:
        value = swagger_func.get_so_rewards(env, date_info)
    else:  #
        value_ = swagger_func.get_so_rewards(env, date_info)
        value = value_[so_id-1]

    result['message'] = "Success"        
    result['result'] = value        
        
    return result



# som rewards
@app.get("/Mongo/get/som_rewards", summary="som_rewards 조회", 
        description="date 입력으로 so_rewards 값 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 date_info 기준, mongoDB의 snapshots 조회",
                "content": {
                    "application/jsomn": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("checkpoint", "64b95a6b83fa5faf549622dc"),
                                        ("soId", "1"),        
                                        ("memberId", "1"),        
                                        ("protocolId", "1"),        
                                        ("address", "0xe68F32846F1CB1E924aB3E320028154451D68049"),        
                                        ("reward", "0"),                             
                                        ("createdAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_som_rewards(
    env: str = Query("stg", description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24"),
    project: Project = Query(Project.모두, description="전체 프로젝트 검색 -> 모두  \nApp에서만 검색    -> App  \nFlux에서만 검색    -> Flux"),
    range: Range = Query(Range.모두, description="전체 유저 검색 -> 모두  \n 특정 유저 검색 -> 일부"),
    user_id: Optional[str] = Query(None, description="조회할 user_id를 입력하세요."),
    download_type: DownloadType = Query(DownloadType.NONE, description="range값이 모두일 경우 json or csv 선택")
    ):

    result = {}
    if range == Range.모두:
        if project == Project.모두:
            data = swagger_func.get_som_rewards(env, date_info)
            if download_type == DownloadType.json:
                filename = "data.json.gz"            
                with gzip.open(filename, "wb") as f:
                    json_data = json.dumps(data).encode("utf-8")
                    f.write(json_data)

                response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

                return response
            
            elif download_type == DownloadType.csv:
                zipname = "data.csv.gz" 
                filename = "data.csv" 

                json_data = json.dumps(data)                 
                data = pd.read_json(json_data)

                # CSV 파일로 변환하여 저장
                data.to_csv(filename, index=False)

                with zipfile.ZipFile(zipname, 'w') as zipf:
                    zipf.write(filename, os.path.basename(filename))                

                response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

                return response

        elif project == Project.App:
            values = swagger_func.get_som_rewards(env, date_info)
            data = [item for item in values if item.get('protocolId') == 1]
            if download_type == DownloadType.json:
                filename = "data.json.gz"            
                with gzip.open(filename, "wb") as f:
                    json_data = json.dumps(data).encode("utf-8")
                    f.write(json_data)

                response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

                return response
            
            elif download_type == DownloadType.csv:
                zipname = "data.csv.gz" 
                filename = "data.csv" 

                json_data = json.dumps(data)                 
                data = pd.read_json(json_data)

                # CSV 파일로 변환하여 저장
                data.to_csv(filename, index=False)

                with zipfile.ZipFile(zipname, 'w') as zipf:
                    zipf.write(filename, os.path.basename(filename))                

                response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

                return response

        elif project == Project.Flux:
            values = swagger_func.get_som_rewards(env, date_info)
            data = [item for item in values if item.get('protocolId') == 2]
            if download_type == DownloadType.json:
                filename = "data.json.gz"            
                with gzip.open(filename, "wb") as f:
                    json_data = json.dumps(data).encode("utf-8")
                    f.write(json_data)

                response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

                return response
            
            elif download_type == DownloadType.csv:
                zipname = "data.csv.gz" 
                filename = "data.csv" 

                json_data = json.dumps(data)                 
                data = pd.read_json(json_data)

                # CSV 파일로 변환하여 저장
                data.to_csv(filename, index=False)

                with zipfile.ZipFile(zipname, 'w') as zipf:
                    zipf.write(filename, os.path.basename(filename))                

                response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

                return response

        
    elif range == Range.일부:
        db = rdb_set(env)
        cursor1 = db.cursor(pymysql.cursors.DictCursor)
        sql = f"SELECT id FROM kstadium_main.`member` WHERE user_id = '{user_id}';"
        cursor1.execute(sql)
        rows = cursor1.fetchall()
        memberid = rows[0]['id']

        if project == Project.모두:
            values = swagger_func.get_som_rewards(env, date_info)
            value = [item for item in values if item.get('memberId') == memberid]
            # with open(f'/Users/{username}/Downloads/{str(date_info+address)+"+모두(APP+FLUX)"}.json', 'w') as f:
            #     json.dump(values, f, default = myconverter)
            # value = f'/Users/{username}/Downloads/{str(date_info+address)+"+모두(APP+FLUX)"}.json' + " 파일을 확인하세요."

        elif project == Project.App:
            values = swagger_func.get_som_rewards(env, date_info)
            value = [item for item in values if item.get('memberId') == memberid and item.get('protocolId') == 1]
            # with open(f'/Users/{username}/Downloads/{str(date_info+address)+"+APP"}.json', 'w') as f:
            #     json.dump(values, f, default = myconverter)
            # value = f'/Users/{username}/Downloads/{str(date_info+address)+"+APP"}.json' + " 파일을 확인하세요."

        elif project == Project.Flux:
            values = swagger_func.get_som_rewards(env, date_info)
            value = [item for item in values if item.get('memberId') == memberid and item.get('protocolId') == 2]
            # with open(f'/Users/{username}/Downloads/{str(date_info+address)+"+FLUX)"}.json', 'w') as f:
            #     json.dump(values, f, default = myconverter)
            # value = f'/Users/{username}/Downloads/{str(date_info+address)+"+FLUX)"}.json' + " 파일을 확인하세요."

    result['message'] = "Success"   
    result['result'] = value        
        
    return result


# transaction_investment
@app.get("/Mongo/get/transaction_investment", summary="Send to CommunityPool 이력 조회", 
        description="user_id 입력으로 Send to CommunityPool 이력 조회  \n최신 이력 순으로 노출 " , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 user_id 기준, mongoDB의 transaction_investment 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("functionName", "investment"),
                                        ("hash", "0"),        
                                        ("blockNumber", "0"),        
                                        ("from", "0"),        
                                        ("to", "0"),        
                                        ("amount", "0"),        
                                        ("fee", "0"),     
                                        ("createdAt", "2023-07-20T16:00:00"),                         
                                        ("updatedAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_transaction_investment(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    ):

    result = {}
    value = swagger_func.get_transaction_investment(env, user_id)

    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# transaction_delegate
@app.get("/Mongo/get/transaction_delegate", summary="delegate 이력 조회", 
        description="user_id 입력으로 delegate 이력 조회  \n최신 이력 순으로 노출 " , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 user_id 기준, mongoDB의 transaction_delegate 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("functionName", "delegate"),
                                        ("hash", "0"),        
                                        ("blockNumber", "0"),        
                                        ("from", "0"),        
                                        ("to", "0"),        
                                        ("orgId", "0"),
                                        ("amount", "0"),         
                                        ("fee", "0"),     
                                        ("createdAt", "2023-07-20T16:00:00"),                         
                                        ("updatedAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_transaction_delegate(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    project : str = Query(Project.App, description="전체 프로젝트 검색 -> 모두(현재 안됨)  \nApp에서만 검색    -> App  \nFlux에서만 검색    -> Flux"),
    ):

    result = {}
    value = swagger_func.get_transaction_delegate(env, user_id, project)

    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# transaction_undelegate
@app.get("/Mongo/get/transaction_undelegate", summary="undelegate 이력 조회", 
        description="user_id 입력으로 undelegate 이력 조회  \n최신 이력 순으로 노출 " , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 user_id 기준, mongoDB의 transaction_undelegate 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("functionName", "undelegate"),
                                        ("hash", "0"),        
                                        ("blockNumber", "0"),        
                                        ("from", "0"),        
                                        ("to", "0"),        
                                        ("orgId", "0"),
                                        ("amount", "0"),         
                                        ("fee", "0"),     
                                        ("createdAt", "2023-07-20T16:00:00"),                         
                                        ("updatedAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_transaction_undelegate(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    project : str = Query(Project.App, description="전체 프로젝트 검색 -> 모두(현재 안됨)  \nApp에서만 검색    -> App  \nFlux에서만 검색    -> Flux  \n<참고사항> 현재 패널티 1%를 제외한 값으로 노출"),
    ):

    result = {}
    value = swagger_func.get_transaction_undelegate(env, user_id, project)

    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# transaction_claim
@app.get("/Mongo/get/transaction_claim", summary="claim 이력 조회", 
        description="user_id 입력으로 claim 이력 조회  \n최신 이력 순으로 노출 " , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 user_id 기준, mongoDB의 transaction_claim 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("functionName", "claim"),
                                        ("hash", "0"),        
                                        ("blockNumber", "0"),        
                                        ("from", "0"),        
                                        ("to", "0"),        
                                        ("orgId", "0"),
                                        ("amount", "0"),         
                                        ("fee", "0"),     
                                        ("createdAt", "2023-07-20T16:00:00"),                         
                                        ("updatedAt", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_transaction_claim(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    project : str = Query(Project.App, description="전체 프로젝트 검색 -> 모두(현재 안됨)  \nApp에서만 검색    -> App  \nFlux에서만 검색    -> Flux"),
    ):

    result = {}
    value = swagger_func.get_transaction_claim(env, user_id, project)

    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# get_proposal
@app.get("/Mongo/get/proposal", summary="proposal 이력 조회", 
        description="proposal 이력 조회" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 proposal_id 기준, mongoDB의 proposals 이력 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("_id", "0"),
                                        ("txHash", "0"),        
                                        ("title", "0"),        
                                        ("content", "0"),        
                                        ("status", "0"),        
                                        ("isExposed", "0"),
                                        ("endTxHash", "0"),         
                                        ("endStatus", "0"),     
                                        ("createdAt", "2023-07-20T16:00:00"),                         
                                        ("expirationDate", "2023-07-20T16:00:00")
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_proposal(
    env: str = Query('stg', description="실행 환경"),
    proposal_id: str = Query(..., description="조회할 proposal_id 입력"),
    ):

    result = {}
    value = swagger_func.get_proposal(env, proposal_id)

    result['message'] = "Success"        
    result['result'] = value        
        
    return result


# get_voting_histories
@app.get("/Mongo/get/voting_histories", summary="voting_histories 이력 조회", 
        description="voting_histories 이력 조회  \nvotingPower 높은순 정렬" , tags=['MONGO'],
        responses={
            200: {
                "description": "입력한 proposal_id 기준, mongoDB의 voting_histories 이력 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("_id", "0"),
                                        ("proposal", "0"),        
                                        ("soId", "0"),        
                                        ("userId", "0"),        
                                        ("address", "0"),        
                                        ("memberId", "0"),
                                        ("votingPower", "0"),         
                                        ("result", "0"),     
                                        ("createdAt", "2023-07-20T16:00:00"),                         
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_voting_histories(
    env: str = Query('stg', description="실행 환경"),
    proposal_id: str = Query(..., description="조회할 proposal_id 입력"),
    download_type: DownloadType = Query(DownloadType.NONE, description="보기 : NONE  \n다운로드 : json or csv 선택")
    ):

    result = {}
    data = swagger_func.get_voting_histories(env, proposal_id)
    
    if download_type == DownloadType.json:
        filename = "data.json.gz"            
        with gzip.open(filename, "wb") as f:
            json_data = json.dumps(data).encode("utf-8")
            f.write(json_data)

        response = FileResponse(filename, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={filename}"})

        return response
    
    elif download_type == DownloadType.csv:
        zipname = "data.csv.gz" 
        filename = "data.csv" 

        json_data = json.dumps(data)                 
        data = pd.read_json(json_data)

        # CSV 파일로 변환하여 저장
        data.to_csv(filename, index=False)

        with zipfile.ZipFile(zipname, 'w') as zipf:
            zipf.write(filename, os.path.basename(filename))                

        response = FileResponse(zipname, media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={zipname}"})

        return response

    result['message'] = "Success"        
    result['result'] = data        
        
    return result


######################################
#                REWARD              #
######################################

# snapshot_reset
@app.post("/Reward/post/snapshot_reset", summary="snapshot_reset", 
        description=(
            "1. 아래 컬렉션의 데이터를 지정한 날짜의 checkpoint를 기준으로 삭제 진행.  \n"
            "so_snapshots,\n"
            "som_snapshots,\n"
            "tasks,\n"
            
            "2. Explorer API를 통해 최신 Block 번호를 가져와, 오늘 생성된 checkpoint 컬렉션 데이터에 set\n"
            "3. Snapshots 데이터 생성\n"
        ),
        tags=['Reward'],
        responses={
            200: {
                "description": "최신 블록번호를 기준으로 다시 set하여 snapshot 데이터 재생성",
            }
        }
)
def snapshot_reset(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="실행할 날짜  \nex) 2023-07-24"),
    ):

    if env == 'stg':
        result = {}
        data = swagger_func.snapshot_reset(env, date_info)
    else:
        result = {}
        data = "실행 환경은 STG에서만 가능합니다."
            
    result['message'] = "Success"
    result['result'] = data        

    return result


# reward_excute
@app.post("/Reward/post/reward_excute", summary="reward 재분배", 
        description=(
            "1. 아래 컬렉션의 데이터를 오늘 생성된 checkpoint를 기준으로 삭제 진행.  \n"
            "protocol_fees,\n"
            "rewards,\n"
            "so_rewards,\n"
            "som_rewards,\n"
            "tasks,\n"
            "so_snapshots,\n"
            "som_snapshots,\n"
            "inflations\n\n"
    
            "2. Explorer API를 통해 최신 Block 번호를 가져와, 오늘 생성된 checkpoint 컬렉션 데이터에 set\n"
            "3. Inflations 데이터 생성\n"
            "4. Snapshots 데이터 생성\n"
            "5. Rewards 계산 데이터 생성\n"
            "6. 분배 지갑에 분배량 + 600(수수료) 전송 (생성된 Inflations 데이터 참조)\n"
            "7. Reward 분배 실행"
        ),
        tags=['Reward'],
        responses={
            200: {
                "description": "최신 블록번호를 기준으로 다시 set하여 reward 재분배",
            }
        }
)
def reward_excute(
    password : str = Query(..., description="실행 password 입력")
    ):

    if password == 'qa@1234':
        result = {}
        data = swagger_func.reward_excute()
        
        result['message'] = "Success"        
        result['result'] = data        
    else :
        result['message'] = "Fail. Password is incorrect"  

    return result

######################################
#                 RDB                #
######################################

# delegate_log
@app.get("/RDB/get/transaction_delegate_log", summary="delegate 중인 내역 조회", 
        description="user_id 입력으로 현재 delegate 중인 이력 조회  \nso_id 순으로 노출 " , tags=['RDB'],
        responses={
            200: {
                "description": "입력한 user_id 기준, RDB의 kstadium_main -> som 내역 조회",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("so_id", "delegate"),
                                        ("member_id", "0"),        
                                        ("protocol_id", "0"),        
                                        ("sop", "0"),        
                                        ("claim", "0"),        
                                        ("created_at", "0"),
                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def get_rdb_delegate_log(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    project : str = Query(Project.App, description="전체 프로젝트 검색 -> 모두(현재 안됨)  \nApp에서만 검색    -> App  \nFlux에서만 검색    -> Flux"),
    ):

    print(env, user_id, project)

    result = {}
    if project == 'App':
        value = swagger_func.get_rdb_delegate_log(env, user_id, '1')
    elif project == 'Flux':
        value = swagger_func.get_rdb_delegate_log(env, user_id, '2')

    result['message'] = "Success"        
    result['result'] = value        
        
    return result



######################################
#                FLUX                #
######################################

# flux_url
@app.get("/Flux/get/flux_url", summary="flux_accesstoken 및 flux url 확인", 
        description="flux_accesstoken 및 flux url 확인" , tags=['FLUX'],
        responses={
            200: {
                "description": "flux_accesstoken 및 flux url 확인",
                }
                }
        )
def flux_url(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    ):
    password ='medium@1234'
    result = {}
    data = swagger_func.flux_url(user_id,password,env)
    
    result['message'] = "Success"        
    result['access_token'] = data[0]
    result['url'] = data[1]


    return result
    
# accumulate_value
@app.get("/Mongo/get/accumulate_value", summary="누적 값 조회", 
        description=(
            "Project와 FunctionType을 선택하여 누적 값 조회  \n"  
            "### Flux claim의 경우, claim 이벤트와 undelegtae 이벤트의 합을 합산한 값."
            ) , tags=['MONGO'],
        responses={
            200: {
                "description": "Project와 Functiond을 선택하여 누적 값 조회",
                }
                }
        )
def get_accumulate_value(
    env: str = Query('stg', description="실행 환경"),
    project: Project = Query(Project.App, description="모두(현재 안됨.)"),
    functiontype: FunctionType = Query(FunctionType.delegate, description="delegate, undelegate, claim 중 선택"),
    ):

    result = {}
    if project == Project.App:
        if functiontype == FunctionType.delegate:
            value = swagger_func.get_transaction_accumulate_delegate(env,'App')
        elif functiontype == FunctionType.undelegate:
            value = swagger_func.get_transaction_accumulate_undelegate(env,'App')
        elif functiontype == FunctionType.claim:
            value = swagger_func.get_transaction_accumulate_claim(env,'App')

    if project == Project.Flux:
        if functiontype == FunctionType.delegate:
            value = swagger_func.get_transaction_accumulate_delegate(env,'Flux')
        elif functiontype == FunctionType.undelegate:
            value = swagger_func.get_transaction_accumulate_undelegate(env,'Flux')
        elif functiontype == FunctionType.claim:
            value = swagger_func.get_transaction_accumulate_claim(env,'Flux')

    result['message'] = "Success"        
    result['result'] = str(decimal.Decimal(int(value)/int(eth)))
        
    return result


# flux_delegator count
@app.get("/Flux/get/home/delegator_count", summary="Flux delegator 값 조회", 
        description="delegator 값 조회" , tags=['FLUX'],
        responses={
            200: {
                "description": "delegator 값 조회",
                }
                }
        )
def get_flux_delegator(
    env: str = Query('stg', description="실행 환경"),
    ):

    result = {}
    value = swagger_func.get_flux_delegator(env)

    result['message'] = "Success"        
    result['result'] = value
        
    return result


# flux_so list 조회
@app.get("/Flux/get/delegate/so_list", summary="so_list 값 조회", 
        description="env를 참조하여 so_list 조회" , tags=['FLUX'],
        responses={
            200: {
                "description": "env를 참조하여 so_list 조회",
                }
                }
        )
def get_flux_so_list(
    env: str = Query('stg', description="실행 환경"),
    ):

    result = {}
    value = swagger_func.get_flux_so_list(env)

    result['message'] = "Success"        
    result['result'] = value
        
    return result


# flux_arr
@app.get("/Flux/get/delegate/arr", summary="Flux arr 값 조회", 
        description="date를 참조하여 arr값 조회" , tags=['FLUX'],
        responses={
            200: {
                "description": "env와 date를 참조하여 arr값 조회",
                }
                }
        )
def get_flxu_arr(
    env: str = Query('stg', description="실행 환경"),
    date_info: str = Query(today, description="조회할 날짜  \nex) 2023-07-24")
    ):

    result = {}
    value = swagger_func.get_flux_arr(env, date_info)

    result['message'] = "Success"        
    result['result'] = value
        
    return result


# flux_total_delegated_amount
@app.get("/Flux/get/delegate/total_delegated_amount", summary="Flux total_delegated_amount 값 조회", 
        description="env와 user_id를 참조하여 flux에서의 total_delegated_amount 값 조회" , tags=['FLUX'],
        responses={
            200: {
                "description": "env와 user_id를 참조하여 flux에서의 total_delegated_amount 값 조회",
                }
                }
        )
def get_flux_total_delegated_amount(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    ):

    result = {}
    value = swagger_func.get_flux_total_delegated_amount(env, user_id)

    result['message'] = "Success"        
    result['result'] = value
        
    return result


# flux_total_claimable_ksta
@app.get("/Flux/get/delegate/total_claimable_ksta", summary="Flux total_claimable_ksta 값 조회", 
        description="env와 user_id를 참조하여 flux에서의 total_claimable_ksta 값 조회" , tags=['FLUX'],
        responses={
            200: {
                "description": "env와 user_id를 참조하여 flux에서의 total_claimable_ksta 값 조회",
                }
                }
        )
def get_flux_total_claimable_ksta(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    ):

    result = {}
    value = swagger_func.get_flux_total_claimable_ksta(env, user_id)

    result['message'] = "Success"        
    result['result'] = value
        
    return result


# excute_delegate
@app.post("/Flux/post/excute_delegate", summary="다수의 SO에 위임", 
        description=
        "## 위임 가능한 조건  \n"
        "App : 소수점 5자리까지 위임 가능  \n"
        "Flux : 소수점 14자리까지 위임 가능  \n"
        "## 위임 Tip  \n"
        "1개의 SO에만 위임하고 싶을 경우, start_soid와 end_soid를 같게 설정  \n" , tags=['FLUX'],
        responses={
            200: {
                "description": "위임 실행된 이력들 노출",
                "content": {
                    "application/json": {
                            "example": {
                                "message": "Success",
                                "result": OrderedDict([            
                                        ("so_id", 0),
                                        ("amount", 0),        
                                        ("message", ""),        

                                    ])
                                    }
                                    }
                            
                            } 
                }
                }
        )
def excute_delegate(
    env: str = Query('stg', description="실행 환경"),
    user_id: str = Query(..., description="조회할 user_id 입력"),
    start_soid: int = Query(..., description="시작 so_id 입력"),
    end_soid: int = Query(..., description="마지막 soi_id 입력"),
    delegate_amount: float = Query(..., description="위임할 값 입력"),
    project : str = Query('App', description="App 위임    -> App  \nFlux 위임    -> Flux"),
    ):

    result = {}
    value = swagger_func.excute_delegate(env, user_id, start_soid, end_soid, delegate_amount, project)
    
    
    result['message'] = "Success"        
    result['result'] = value        
        
    return result



if "LAMBDA_RUNTIME_DIR" in os.environ:
    handler = Mangum(app)
else:
    if __name__ == '__main__':
        uvicorn.run(app, host="0.0.0.0", port=8000)
