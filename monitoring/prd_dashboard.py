#qa_dashboard
from functools import total_ordering
from unicodedata import decimal
import gspread
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from api import ks_api, ex_api, flux_api, new_groundchain_api
import platform
import pymongo
import pymysql
from datetime import datetime, timedelta  # 수정된 부분
from bson.objectid import ObjectId
import requests
import time
import json
import decimal

env = 'prd'
ex_api.set_env(env)
today_date = datetime.now().strftime('%Y-%m-%d')
checkpoint_id = ''
date = datetime.now()
eth = 1000000000000000000
# yesterday = datetime.now() - timedelta(days=1)
# yesterday_date = yesterday.date()
# start_time = datetime(yesterday_date.year, yesterday_date.month, yesterday_date.day, 0, 0, 0)
# end_time = datetime(yesterday_date.year, yesterday_date.month, yesterday_date.day, 23, 59, 59)

########################## 구글시트 설정 #################################

sysOS = platform.system()
if sysOS == "Windows":
    gs = gspread.service_account('')
elif sysOS == "Linux":
    gs = gspread.service_account('') #참조할 구글시트에 공유 되어있는 json 파일 추가
elif sysOS == "Darwin":
    gs = gspread.service_account("")
else:
    print("Unknown operating system.")

sheet_file = f"{env}_qa_dashboard"
top_sh = gs.open(sheet_file).worksheet("")
dex_sh = gs.open(sheet_file).worksheet("")
som_count_sh = gs.open(sheet_file).worksheet("")
so_reward_sh = gs.open(sheet_file).worksheet("")
so_delegate_sh = gs.open(sheet_file).worksheet("")
kstadium_so_sh = gs.open(sheet_file).worksheet("")
kstadium_som_sh = gs.open(sheet_file).worksheet("")

all_memberid_col = kstadium_som_sh.col_values(1)

sysOS = platform.system()
if sysOS == "Windows":
    gs2 = gspread.service_account('')
elif sysOS == "Linux":
    gs2 = gspread.service_account('') #참조할 구글시트에 공유 되어있는 json 파일 추가
elif sysOS == "Darwin":
    gs2 = gspread.service_account("")
else:
    print("Unknown operating system.")

sheet_file_ = ""
daily_block_sh = gs2.open(sheet_file_).worksheet("")

########################## RDB set ############################
# RDB 접속하기 
# stg
if env == 'stg':
    stg_kstadium_rest_api = ''
    stg_myid = ''
    stg_mypasswd = ''
    rdb = pymysql.connect(host=stg_kstadium_rest_api, port=3306, user=stg_myid, passwd=stg_mypasswd, db='', charset='utf8')
    cursor1 = rdb.cursor(pymysql.cursors.DictCursor)
#prd
elif env ==  'prd':
    prd_kstadium_rest_api = ''
    prd_myid = ''
    prd_mypasswd = ''
    rdb = pymysql.connect(host=prd_kstadium_rest_api, port=3306, user=prd_myid, passwd=prd_mypasswd, db='', charset='utf8')
    cursor1 = rdb.cursor(pymysql.cursors.DictCursor)
else:
    print("잘못 입력되었습니다 다시 수행하세요.")
    exit()


########################## mongoDB set ############################

# mongoDB URI
# dev
if env == 'dev':
    if sysOS == "Windows":
        uri = ''
    elif sysOS == "Linux":
        pass
    elif sysOS == "Darwin":
        uri = ''
    else:
        print("Unknown operating system.")

# stg
elif env == 'stg':
    if sysOS == "Windows":
        uri = ''
    elif sysOS == "Linux":
        pass
    elif sysOS == "Darwin":
        uri = ''
    else:
        print("Unknown operating system.")

# prd
elif env == 'prd':
    if sysOS == "Windows":
        uri = ''
    elif sysOS == "Linux":
        pass
    elif sysOS == "Darwin":
        uri = ''
    else:
        print("Unknown operating system.")


# MongoDB 클라이언트 생성
client = pymongo.MongoClient(uri)
# 데이터베이스 선택
db = client['kstadium_main']


########################################################################################################################################################################
class Explorer():
    # 당일 UTC+8 기준 00:00:00의 블록번호 계산
    def ex_blocknumber():
        # print("=================== block number 확인 ===================")
        # 최근 블록 번호 
        cur_block = ex_api.get_blocks(1,1)[0]['blockNumber']
        cur_block_info = ex_api.get_block_blocks(cur_block)
        cur_block_ts = cur_block_info['timeStamp']
        cur_block_dt = datetime.fromtimestamp(int(cur_block_ts))
        cur_block_time = cur_block_dt.strftime("%H:%M:%S")
        cur_block_time_split = cur_block_time.split(':')

        # 최근 블록 번호 시/분/초를 초 단위로 환산
        hour   = int(cur_block_time_split[0]) * 3600 # 분 단위 오차 계산 및 추출
        minute = int(cur_block_time_split[1]) * 60 # 분 단위 오차 계산 및 추출
        second = int(cur_block_time_split[2]) # 초 단위 오차 추출
        past_time = hour + minute + second

        while True:
            # 최근 블록 번호에서 초 단위 환산한만큼 차감하여 00:00:00 블록 번호 확인
            cal_block = cur_block - past_time + 3600 -86400
            cal_block_info = ex_api.get_block_blocks(cal_block)
            cal_block_ts = cal_block_info['timeStamp']
            cal_block_dt = datetime.fromtimestamp(int(cal_block_ts))
            cal_block_time = cal_block_dt.strftime("%H:%M:%S")
            cal_block_date = cal_block_dt.strftime("%Y-%m-%d")

            if cal_block_time == "01:00:00":
                # 오늘 시작블록
                today_start_block = cur_block - past_time + 3600
                today_block_info = ex_api.get_block_blocks(today_start_block)
                today_block_ts = today_block_info['timeStamp']
                today_block_dt = datetime.fromtimestamp(int(today_block_ts))
                today_block_date = today_block_dt.strftime("%Y-%m-%d")

                # print("오늘 시작블록 : " + str(today_start_block))
                # print("======================================")

                # 어제 시작블록
                start_block = cal_block
                # print("어제 시작블록 : " + str(start_block))

                # 어제 끝블록
                oneday_block = 86400
                end_block_ = start_block + oneday_block -1
                end_block_info = ex_api.get_block_blocks(end_block_)
                end_block_ts = end_block_info['timeStamp']
                end_block_dt = datetime.fromtimestamp(int(end_block_ts))
                end_block_time = end_block_dt.strftime("%H:%M:%S")

                while True:
                    if end_block_time == "00:59:59":
                        end_block = end_block_
                        # print("어제 끝 블록  : " + str(end_block))
                        True
                    else:
                        end_block_time_split = end_block_time.split(':')
                        # 최근 블록 번호 시/분/초를 초 단위로 환산
                        hour   = int(end_block_time_split[0]) * 3600 # 분 단위 오차 계산 및 추출
                        minute = int(end_block_time_split[1]) * 60 # 분 단위 오차 계산 및 추출
                        second = int(end_block_time_split[2]) # 초 단위 오차 추출
                        past_time = hour + minute + second
                    
                        # 최근 블록 번호에서 초 단위 환산한만큼 차감하여 00:00:00 블록 번호 확인
                        end_block_ = end_block - past_time -1
                        end_block_info = ex_api.get_block_blocks(end_block_)
                        end_block_ts = end_block_info['timeStamp']
                        end_block_dt = datetime.fromtimestamp(int(end_block_ts))
                        end_block_time = end_block_dt.strftime("%H:%M:%S")
                        False
                    return today_start_block, start_block, end_block
            else: 
                print(cal_block_time)
                False

class mongo():
    def get_checkpoints(env, date_info):
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
            result.append(result_dic)

        # 쿼리문의 결과를 dic형태로 반환
        return result_dic['checkpoint']
    
    def get_inflations(env, date_info):
        checkpoint = mongo.get_checkpoints(env, date_info)

        # 컬렉션 선택
        collection = db['inflations']

        # 쿼리문 실행
        query_results = collection.find({'checkpoint':ObjectId(checkpoint)})
        result = []
        for data in query_results:
            result_dic = {}
            result_dic['transactionCount'] = data['transactionCount']
            print(result_dic['transactionCount'])
            result.append(result_dic)

        # 쿼리문의 결과를 dic형태로 반환
        return result_dic['transactionCount']

class Top:
    def user_count():
        sql = "SELECT count(address) FROM kstadium_main.member;"
        cursor1.execute(sql)
        rows = cursor1.fetchall()
        user_count = (rows[0]['count(address)'])
        top_sh.update_acell("A2", today_date)
        top_sh.update_acell("B2", user_count)

    def real_user_count():
        sql = "SELECT COUNT(*) AS row_count FROM (SELECT * FROM kstadium_main.som GROUP BY member_id) AS subquery;"
        cursor1.execute(sql)
        rows = cursor1.fetchall()
        user_count = (rows[0]['row_count'])
        top_sh.update_acell("C2", user_count)

    def today_txn():
        date_info = date.strftime("%Y-%m-%d")
        print(date_info)
        transactionCount = mongo.get_inflations(env, date_info)
        top_sh.update_acell("D2", transactionCount)


class som_count:
    def today_blocknumber():
        print("============================== block number를 조회합니다. =============================")
        collection = db['checkpoints']

        # {createdAt:-1} 정렬을 사용해서 컬렉션에서 문서를 찾습니다.
        # sort 메서드는 -1을 사용해서 내림차순으로 정렬하고,
        # limit 메서드는 한 개의 결과만 반환하도록 합니다.
        result = collection.find().sort('createdAt', -1).limit(1)

        # 문서를 반복 처리하고 각 문서를 출력합니다.
        doc = None  # doc 변수를 초기화합니다.
        for doc in result:
            print(doc)

        if doc:  # 문서가 존재하면 다음을 수행합니다.
            blocknumber = doc['blockNumber']
            # 'createdAt' 필드가 datetime 객체인지 확인하고 timedelta를 추가합니다.
            if isinstance(doc['createdAt'], datetime):
                createdAt = doc['createdAt'] + timedelta(days=1)  # 수정된 부분
                createdAt = createdAt.strftime("%Y-%m-%d")

                print("Today blocknumber            : ", blocknumber, createdAt)

                som_count_sh.update_acell("A2", createdAt)
                so_reward_sh.update_acell("A2", createdAt)
                so_delegate_sh.update_acell("A2", createdAt)

                return blocknumber
            else:
                # 'createdAt' 필드가 datetime 객체가 아닌 경우 오류 메시지를 출력합니다.
                print("'createdAt' is not a datetime object")
                return None  # 문제가 있을 경우 None을 반환합니다.
        else:
            print("No document found")
            return None  # 문서가 없을 경우 None을 반환합니다.

    def db_checkpoint(blocknumber):
        print("============================== checkpoint 를 조회합니다. =============================")
        global checkpoint_id

        # 'checkpoints' 컬렉션 선택
        collection = db['checkpoints']

        # 데이터 조회
        query = {'blockNumber':blocknumber}
        query_result = collection.find(query)
        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['_id'] = doc['_id']
            result_dic['blockNumber'] = doc['blockNumber']
            result_dic['createdAt'] = doc['createdAt']
            result_li.append(result_dic)

        checkpoint_id = (result_li[0]['_id'])
        blocknumber = (result_li[0]['blockNumber'])
        createdAt = (result_li[0]['createdAt'])
        
        print(str(checkpoint_id))

        return checkpoint_id

    def user_count(checkpoint_id):
        print("============================== SO별 유저 수를 조회합니다. =============================")
        collection = db['so_snapshots']
        # 데이터 조회
        query = {'checkpoint':checkpoint_id}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['name'] = doc['name']
            result_dic['somCount'] = doc['somCount']

            result_li.append(result_dic['somCount'])

            print(str(result_dic['soId']) + ' ' + str(result_dic['name']) + ' ' + str(result_dic['somCount']))

        start_col = 'B'
        end_col_index = ord(start_col) - ord('A') + len(result_li) -1 # ASCII 값을 사용하여 열 인덱스 계산
        end_col = chr(ord('A') + end_col_index)

        # 2번 행을 기준으로 열 범위를 설정합니다. 여기서는 하나의 행만 업데이트하므로 시작 행과 끝 행이 동일합니다.
        range_string = '{}2:{}2'.format(start_col, end_col)  # B2, C2, ... 형태로 범위를 구성합니다.
        cell_list = som_count_sh.range(range_string)

        # result_li의 각 값을 해당 열의 2번 행에 할당합니다.
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i])
        # 변경된 셀 값을 실제 시트에 업데이트합니다.
        som_count_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        som_count_sh.insert_row(['', '', '', '', '', '', ''],2)

    def daily_so_reward(checkpoint_id):
        print("============================== SO별 리워드 값을 조회합니다. =============================")
        collection = db['so_rewards']
        # 데이터 조회
        query = {'checkpoint':checkpoint_id}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['reward'] = doc['reward']

            result_li.append(decimal.Decimal(int(result_dic['reward']))/int(eth))
            print(str(result_dic['soId']) + ' ' + str(result_dic['reward']))

        start_col = 'B'
        end_col_index = ord(start_col) - ord('A') + len(result_li) -1 # ASCII 값을 사용하여 열 인덱스 계산
        end_col = chr(ord('A') + end_col_index)

        # 2번 행을 기준으로 열 범위를 설정합니다. 여기서는 하나의 행만 업데이트하므로 시작 행과 끝 행이 동일합니다.
        range_string = '{}2:{}2'.format(start_col, end_col)  # B2, C2, ... 형태로 범위를 구성합니다.
        cell_list = so_reward_sh.range(range_string)

        # result_li의 각 값을 해당 열의 2번 행에 할당합니다.
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i])
        # 변경된 셀 값을 실제 시트에 업데이트합니다.
        so_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        so_reward_sh.insert_row(['', '', '', '', '', '', ''],2)

    def daily_so_delegate(checkpoint_id):
        print("============================== SO별 위임 양을 조회합니다. =============================")
        collection = db['so_snapshots']
        # 데이터 조회
        query = {'checkpoint':checkpoint_id}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['name'] = doc['name']
            result_dic['sop'] = doc['sop']

            result_li.append(decimal.Decimal(int(result_dic['sop']))/int(eth))

            print(str(result_dic['soId']) + ' ' + str(result_dic['name']) + ' ' + str(result_dic['sop']))

        start_col = 'B'
        end_col_index = ord(start_col) - ord('A') + len(result_li) -1 # ASCII 값을 사용하여 열 인덱스 계산
        end_col = chr(ord('A') + end_col_index)

        # 2번 행을 기준으로 열 범위를 설정합니다. 여기서는 하나의 행만 업데이트하므로 시작 행과 끝 행이 동일합니다.
        range_string = '{}2:{}2'.format(start_col, end_col)  # B2, C2, ... 형태로 범위를 구성합니다.
        cell_list = so_delegate_sh.range(range_string)

        # result_li의 각 값을 해당 열의 2번 행에 할당합니다.
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i])
        # 변경된 셀 값을 실제 시트에 업데이트합니다.
        so_delegate_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        so_delegate_sh.insert_row(['', '', '', '', '', '', ''],2)


# Top
Top.user_count()
Top.real_user_count()
Top.today_txn()
top_sh.insert_row(['', '', '', '', '', '', ''],2)  # 행추가

# som_count
blocknumber = som_count.today_blocknumber()
checkpoint_id = som_count.db_checkpoint(blocknumber)
som_count.user_count(checkpoint_id)
som_count.daily_so_reward(checkpoint_id)
som_count.daily_so_delegate(checkpoint_id)
