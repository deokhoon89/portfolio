from functools import total_ordering
from tabnanny import check
from tkinter import TRUE
import pymongo
import gspread

import decimal
import pymysql
from bson.objectid import ObjectId
import platform
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from api import ex_api, flux_api, new_groundchain_api, ks_api, ex_api
import datetime
import time

env = 'prd'
sheet_file = f"{env}_reward"
sheet_file2 = f"{env}_qa_dashboard"
ex_api.set_env(env)
ks_api.set_env(env)
new_groundchain_api.set_env(env)


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

snapshot_sh = gs.open(sheet_file).worksheet("")
so_cal_sh = gs.open(sheet_file).worksheet("")
user_reward_sh = gs.open(sheet_file).worksheet("")
leader_reward_sh = gs.open(sheet_file).worksheet("")
daily_blocknumber_sh = gs.open(sheet_file).worksheet("")
daily_block_sh = gs.open(sheet_file).worksheet("")
checkpoint_sh = gs.open(sheet_file).worksheet("")
result_sh = gs.open(sheet_file).worksheet("")
inflation_sh = gs.open(sheet_file).worksheet("")
reward_result_sh = gs.open(sheet_file).worksheet("")
kstadium_som_sh = gs.open(sheet_file2).worksheet("")

######################### mongoDB 설정 #################################

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

#######################################################################

######################### RDB 설정 #################################

# DB 접속하기 
# stg
if env == 'stg':
    stg_kstadium_rest_api = ''
    stg_myid = ''
    stg_mypasswd = ''
    rdb = pymysql.connect(host=stg_kstadium_rest_api, port=3306, user=stg_myid, passwd=stg_mypasswd, db='', charset='utf8')
#prd
elif env ==  'prd':
    prd_kstadium_rest_api = ''
    prd_myid = ''
    prd_mypasswd = ''
    rdb = pymysql.connect(host=prd_kstadium_rest_api, port=3306, user=prd_myid, passwd=prd_mypasswd, db='', charset='utf8')
else:
    print("잘못 입력되었습니다 다시 수행하세요.")
    exit()

#######################################################################


######################### 변수 초기 설정 #################################
eth = 1000000000000000000
checkpoint_id = ''
flux_controller = ''
treasury_address = ''
orgsmgr = ''

datetime_ = datetime.datetime.now().strftime("%Y"+"-"+"%m"+"-"+"%d")
datetime_db = datetime.datetime.now().strftime("%Y%m%d")

# 로그 시간대 설정 (오늘)
start_time = int(time.mktime(time.strptime('{} 06:00:00'.format(datetime_), '%Y-%m-%d %H:%M:%S')) * 1000) # 특정 날짜의 ##시 ##분 ##초
end_time = int(time.mktime(time.strptime('{} 08:00:00'.format(datetime_), '%Y-%m-%d %H:%M:%S')) * 1000) # 특정 날짜의 ##시 ##분 ##초

#######################################################################


#######################################################################

class Explorer:
    def treasury_before_check():
        print("===================== TREASURY CEHCK =====================")
        treasury_vault = ex_api.get_accounts_address(treasury_address)['balance']
        treasury_vault_eth = str(treasury_vault)
        print(treasury_vault_eth)

        reward_result_sh.update_acell("E2",treasury_vault_eth)

    def treasury_after_check():
        print("===================== TREASURY CEHCK =====================")
        treasury_vault = ex_api.get_accounts_address(treasury_address)['balance']
        treasury_vault_eth = str(treasury_vault)
        print(treasury_vault_eth)

        reward_result_sh.update_acell("F2",treasury_vault_eth)

    def treasury_cal_check():   
        print("===================== TREASURY CAL CEHCK =====================")
        before_treasury = reward_result_sh.get_values("E2")[0][0]
        after_treasury = reward_result_sh.get_values("F2")[0][0]

        cal_treasury = round(decimal.Decimal(after_treasury) - decimal.Decimal(before_treasury),5)
        print(cal_treasury)
        reward_result_sh.update_acell("G2",str(cal_treasury))

        estimate_treasury = reward_result_sh.get_values("H2")[0][0]

        result_treasury = decimal.Decimal(cal_treasury) - decimal.Decimal(estimate_treasury)

        if result_treasury < 0.0000000001 and result_treasury > -0.0000000001:
            reward_result_sh.update_acell("J2","PASS")
        else:
            reward_result_sh.update_acell("J2","FAIL")

        # QA 계산 treasury 값 확인
        treasury_col = user_reward_sh.col_values(42)
        treasury_value = 0
        for i in range(2,len(treasury_col)):
            treasury_value += decimal.Decimal(treasury_col[i])
        
        treasury = round(decimal.Decimal(treasury_value) * decimal.Decimal(0.1),5)
        reward_result_sh.update_acell("I2", str(treasury))
        reward_result_sh.insert_row(['', '', '', '', '', '', ''],2) 


class Blocknumber:
    def today_blocknumber():
        collection = db['checkpoints']

        # {createdAt:-1} 정렬을 사용해서 컬렉션에서 문서를 찾습니다. 
        # sort 메서드는 -1을 사용해서 내림차순으로 정렬하고, 
        # limit 메서드는 한 개의 결과만 반환하도록 합니다.
        result = collection.find().sort('createdAt', -1).limit(1)

        # 결과를 출력합니다.
        for doc in result:
            print(doc)

        blocknumber = doc['blockNumber']
        createdAt = doc['createdAt'] + datetime.timedelta(days=1)
        createdAt = createdAt.strftime("%Y-%m-%d")

        print("Today blocknumber            : ", blocknumber,createdAt)
        
        checkpoint_sh.update_acell("A2",createdAt)
        checkpoint_sh.update_acell("C2",blocknumber)
        
        return blocknumber

    def yesterday_blocknumber():
        collection = db['checkpoints']

        # {createdAt:-1} 정렬을 사용해서 컬렉션에서 문서를 찾습니다. 
        # sort 메서드는 -1을 사용해서 내림차순으로 정렬하고, 
        # limit 메서드는 한 개의 결과만 반환하도록 합니다.
        result = collection.find().sort('createdAt', -1).limit(2)

        # 결과를 출력합니다.
        doc_li = []
        for doc in result:
            doc_li.append(doc)

        start_blocknumber = doc_li[1]['blockNumber']
        start_createdAt = doc_li[1]['createdAt'] + datetime.timedelta(days=1)
        start_createdAt = start_createdAt.strftime("%Y-%m-%d")

        print("Yesteroday START blocknumber : ", start_blocknumber,start_createdAt)

        end_blocknumber = doc_li[0]['blockNumber'] -1
        end_createdAt = doc_li[1]['createdAt'] + datetime.timedelta(days=1)
        end_createdAt = end_createdAt.strftime("%Y-%m-%d") 
            
        daily_blocknumber_sh.update_acell("A2", start_createdAt)
        daily_blocknumber_sh.update_acell("C2", start_blocknumber)
    
        print("Yesteroday End blocknumber   : ", end_blocknumber,end_createdAt)

        daily_blocknumber_sh.update_acell("E2", end_blocknumber)
        daily_blocknumber_sh.insert_row(['', '', '', '', '', '', ''],2) 

        return start_createdAt


class Db_snapshot_reward:   
    # 당일 시작블록 번호 기준 -> checkpoint 컬렉션에서 _id 및 시작블록 확인
    def db_checkpoint(blocknumber_):

        print("===================== Checkpoint 확인 ===================== ")
        global checkpoint_id

        # 'checkpoints' 컬렉션 선택
        collection = db['checkpoints']
        
        # 데이터 조회
        query = {'blockNumber':blocknumber_}
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

        checkpoint_sh.update_acell("C2",blocknumber)
        if blocknumber_ == blocknumber:
            checkpoint_sh.update_acell("D2",str(checkpoint_id))
            checkpoint_sh.update_acell("E2","PASS")
            result_sh.update_acell("C3","PASS")

        else:
            checkpoint_sh.update_acell("E2","FAIL")
            result_sh.update_acell("C3","FAIL")

        checkpoint_sh.insert_row(['', '', '', '', '', '', ''],2)
        
        print(checkpoint_id, blocknumber, createdAt)

        return checkpoint_id, blocknumber, createdAt

    def db_yesterday_checkpoint():

        print("===================== Yesterday Checkpoint 확인 ===================== ")
        # 'checkpoints' 컬렉션 선택
        collection = db['checkpoints']
        
        # 데이터 조회
        query = [{"$sort": {"blockNumber": -1}}]
        query_result = collection.aggregate(query)
        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['_id'] = doc['_id']
            result_dic['blockNumber'] = doc['blockNumber']
            result_dic['createdAt'] = doc['createdAt']
            result_li.append(result_dic)

        yesterday_checkpoint_id = (result_li[1]['_id'])
        yesterday_blocknumber = (result_li[1]['blockNumber'])
        yesterday_createdAt = (result_li[1]['createdAt'])
        
        print(yesterday_checkpoint_id, yesterday_blocknumber, yesterday_createdAt)

        return yesterday_checkpoint_id, yesterday_blocknumber, yesterday_createdAt

    def db_blockreward():
        # 데이터베이스 선택
        collection = db['blocks']

        start = int(daily_blocknumber_sh.get_values("C3")[0][0])
        end = int(daily_blocknumber_sh.get_values("E3")[0][0])

        block_number_li = []
        block_reward_li = []
        block_timestamp_li = []
        utc9_li = []
        utc9_second_li = []

        for number in range(start,end+1):
            query = {'number': number}
            query_result = collection.find_one(query)
            
            block_reward = str(decimal.Decimal(int(query_result['blockReward']) / int(eth)))
            block_timestamp = query_result['timestamp']

            dt = datetime.datetime.fromtimestamp(int(block_timestamp))
            # 시/분/초 
            time_utc9 = dt.strftime("%H:%M:%S")
            
            # 시/분/초를 각각 나누어 초단위로 환산
            hour = dt.hour
            minute = dt.minute
            second = dt.second
            time_utc9_second = hour * 3600 + minute * 60 + second

            print(str(number),str(block_reward),str(block_timestamp),str(time_utc9),str(time_utc9_second))

            block_number_li.append(number)
            block_reward_li.append(block_reward)
            block_timestamp_li.append(block_timestamp)
            utc9_li.append(time_utc9)    
            utc9_second_li.append(time_utc9_second)
            
        cell_list = daily_block_sh.range('A{}:A{}'.format('2',len(block_number_li)+1))
        for i, cell in enumerate(cell_list):
            cell.value = block_number_li[i]
        daily_block_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = daily_block_sh.range('B{}:B{}'.format('2',len(block_reward_li)+1))
        for i, cell in enumerate(cell_list):
            cell.value = block_reward_li[i]
        daily_block_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = daily_block_sh.range('C{}:C{}'.format('2',len(block_timestamp_li)+1))
        for i, cell in enumerate(cell_list):
            cell.value = block_timestamp_li[i]
        daily_block_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = daily_block_sh.range('D{}:D{}'.format('2',len(utc9_li)+1))
        for i, cell in enumerate(cell_list):
            cell.value = utc9_li[i]
        daily_block_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = daily_block_sh.range('E{}:E{}'.format('2',len(utc9_second_li)+1))
        for i, cell in enumerate(cell_list):
            cell.value = utc9_second_li[i]
        daily_block_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

    # checkpoint_id 기준 -> so_snapshot 컬렉션 조회 
    # 시작블록 번호로 Contract에 호출하여 얻은 값
    def db_so_snapshot():
        print("===================== SO snapshot 입력 ===================== ")
        # 'so_snapshots' 컬렉션 선택
        collection = db['so_snapshots']
        # 데이터 조회
        print(checkpoint_id)
        query = {'checkpoint':ObjectId(checkpoint_id)}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['name'] = doc['name']
            result_dic['sop'] = doc['sop']
            result_dic['claim'] = doc['claim']
            result_dic['ranking'] = doc['ranking']
            result_dic['somCount'] = doc['somCount']
            result_dic['ratio'] = doc['ratio']
            result_li.append(result_dic)
        print(result_li)

        cell_list = snapshot_sh.range('B{}:B{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['name'])
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('C{}:C{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['soId'])
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('D{}:D{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['ranking'])
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('E{}:E{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = result_li[i]['sop']
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('F{}:F{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = result_li[i]['claim']
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('G{}:G{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['somCount'])
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('H{}:H{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['checkpoint'])
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = snapshot_sh.range('I{}:I{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['sop'])/eth)
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 
        
        cell_list = snapshot_sh.range('J{}:J{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['ratio'])/eth)
        snapshot_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        return result_li

    # checkpoint_id 기준 -> 시작블록(전날 시작 블록) ~ 끝블록(오늘 시작 블록 -1)의 계산된 블록 리워드 조회
    # inflation, so_reward, communitypool_reward, dev_reward
    def db_inflation():
        print("===================== Infalation 입력 ===================== ")
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

        # so_cal sheet 값 입력 -> inflation 값에서 so_rewards의 경우, 수수료 사용 비용 600 KSTA를 빼고, 어제 리워드 분배 후 남은 값을 더한다.
        # so reward = so_rewards(inflation) - 600 KSTA + remain(어제)
        so_reward = decimal.Decimal(int(result_li[0]['soReward'])/int(eth))
        so_cal_sh.update_acell("F1", str(so_reward))
        inflation_sh.update_acell("O3", str(so_reward))
        print("어제 리워드 남은 양 계산 전 : " + str(so_reward))
        
        # 어제 날짜의 체크포인트를 참조해 리워드 남은양을 확인.
        yesterday_checkpoint_id = Db_snapshot_reward.db_yesterday_checkpoint()[0]
        print(yesterday_checkpoint_id)
        cal_collection = db['rewards']
        cal_query = {'checkpoint':ObjectId(yesterday_checkpoint_id)}
        cal_query_result = cal_collection.find(cal_query)
        
        cal_result_li = []
        for cal_doc in cal_query_result:
            cal_result_dic = {}
            try:
                # 600 KSTA
                cal_result_dic['spareFee'] = cal_doc['spareFee']
                # 실제 발생된 FEE
                cal_result_dic['fee'] = cal_doc['fee']
                cal_result_li.append(cal_result_dic)
            # 남은양이 없다면 0 반환
            except KeyError:
                cal_result_dic['spareFee'] = 0
                cal_result_dic['fee'] = 0
                
            except IndexError:
                cal_result_dic['spareFee'] = 0
                cal_result_dic['fee'] = 0

        sparefee = decimal.Decimal(int(cal_result_dic['spareFee'])/int(eth))
        fee = decimal.Decimal(int(cal_result_dic['fee'])/int(eth))
        remain = sparefee - fee
        so_cal_sh.update_acell("F2", str(fee))
        so_cal_sh.update_acell("F3", str(remain))

        inflation_sh.update_acell("P3", str(fee))
        inflation_sh.update_acell("Q3", str(remain))

        print("어제 리워드 분배 시 sparefee : " + str(sparefee))
        print("어제 리워드 분배 시 발생된 fee : " + str(fee))
        print("어제 리워드 분배 후 남은 reward : " + str(remain))

        so_reward = so_reward - 600 + remain
        so_cal_sh.update_acell("F4", str(so_reward))
        inflation_sh.update_acell("R3", str(so_reward))
        print("오늘 분배되야할 양 QA 계산 : " + str(so_reward))

        so_cal_sh.update_acell("B1",str(so_reward))
        so_cal_sh.update_acell("B2",str(float(so_reward)*0.7))
        so_cal_sh.update_acell("B3",str(float(so_reward)*0.2))
        so_cal_sh.update_acell("B4",str(float(so_reward)*0.1))


        # 오늘 날짜 리워드 값 mongo DB에서 확인.
        dev_collection = db['rewards']
        # 데이터 조회
        dev_query = {'checkpoint':ObjectId(checkpoint_id)}
        dev_query_result = dev_collection.find(dev_query)
        dev_result_li = []
        for dev_doc in dev_query_result:
            dev_result_dic = {}
            # 인플레이션 - 600 + 어제 리워드 분배 후 남은 양
            dev_result_dic['reward'] = dev_doc['reward']
            dev_result_li.append(dev_result_dic)

        dev_so_reward = decimal.Decimal(int(dev_result_dic['reward'])/int(eth))
        so_cal_sh.update_acell("F5", str(dev_so_reward))
        inflation_sh.update_acell("S3", str(dev_so_reward))
        print("오늘 분배되야할 양 Mongo rewards : " + str(dev_so_reward))


        # inflation sheet 값 입력
        collection_ = db['checkpoints']
        result = collection_.find().sort('createdAt', -1).limit(2)

        doc_li = []
        for doc in result:
            doc_li.append(doc)

        start_createdAt = doc_li[1]['createdAt'] + datetime.timedelta(days=1)
        start_createdAt = start_createdAt.strftime("%Y-%m-%d")

        inflation_sh.update_acell("A3",start_createdAt)

        qa_so_reward = daily_block_sh.get_values("I10")[0][0]
        qa_comm_reward = daily_block_sh.get_values("I11")[0][0]
        qa_dev_reward = daily_block_sh.get_values("I12")[0][0]
        db_so_reward = str(decimal.Decimal(result_dic['soReward'])/eth)
        db_comm_reward = str(decimal.Decimal(result_dic['communityReward'])/eth)
        db_dev_reward = str(decimal.Decimal(result_dic['devReward'])/eth)

        inflation_sh.update_acell("B3",qa_so_reward)
        inflation_sh.update_acell("C3",qa_comm_reward)
        inflation_sh.update_acell("D3",qa_dev_reward)
        inflation_sh.update_acell("E3",db_so_reward)
        inflation_sh.update_acell("F3",db_comm_reward)
        inflation_sh.update_acell("G3",db_dev_reward)

        so_reward_cal = inflation_sh.get_values("H3")[0][0]
        comm_reward_cal = inflation_sh.get_values("I3")[0][0]
        dev_reward_cal = inflation_sh.get_values("J3")[0][0]

        if float(so_reward_cal) > -0.00000001 and float(so_reward_cal) < 0.00000001 :
            inflation_sh.update_acell("K3","PASS")
            result_sh.update_acell("C4","PASS")
        else:
            inflation_sh.update_acell("K3","FAIL")
            result_sh.update_acell("C4","FAIL")

        if float(comm_reward_cal) > -0.00000001 and float(comm_reward_cal) < 0.00000001:
            inflation_sh.update_acell("L3","PASS")
            result_sh.update_acell("C5","PASS")
        else:
            inflation_sh.update_acell("L3","FAIL")
            result_sh.update_acell("C5","FAIL")

        if float(dev_reward_cal) > -0.00000001 and float(dev_reward_cal) < 0.00000001:
            inflation_sh.update_acell("M3","PASS")
            result_sh.update_acell("C6","PASS")
        else:
            inflation_sh.update_acell("M3","FAIL")
            result_sh.update_acell("C6","FAIL")
    
        inflation_sh.insert_row(['', '', '', '', '', '', ''],3)  # 행추가

        so_reward = (result_li[0]['soReward'])

        return so_reward

    # checkpoint_id 기준 -> som_snapshot 컬렉션 조회 
    # 시작블록 번호로 Contract에 호출하여 얻은 값
    def db_som_snapshot():
        print("===================== SOM Snapshot 입력 ===================== ")
        # 'som_snapshots' 컬렉션 선택
        collection = db['som_snapshots']
        # 데이터 조회
        query = {'checkpoint': ObjectId(checkpoint_id), 'address': {'$ne': ''}}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['address'] = doc['address']
            result_dic['sop'] = doc['sop']
            result_dic['claim'] = doc['claim']
            result_dic['ratio'] = doc['ratio']
            result_dic['protocolId'] = doc['protocolId']
            result_li.append(result_dic)
        print(result_li)

        result_li = sorted(result_li, key=lambda x: (x['soId'], x['address']))

        cell_list = user_reward_sh.range('F{}:F{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['soId'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = user_reward_sh.range('G{}:G{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['address'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = user_reward_sh.range('H{}:H{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['sop'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = user_reward_sh.range('I{}:I{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['claim'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('J{}:J{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['ratio'])/eth)
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('K{}:K{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['sop'])/eth)
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = user_reward_sh.range('L{}:L{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['claim'])/eth)
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('M{}:M{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str((result_li[i]['protocolId']))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('S{}:S{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['sop'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = user_reward_sh.range('AS{}:AS{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(result_li[i]['soId']) + str(result_li[i]['address'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED') 


    # checkpoint_id 기준 -> so_rewards 컬렉션 조회
    # 당일 SO별 지급되는 reward
    # leader reward 확인 가능한 컬렉션 (so_rewards)
    # SO 리워드 순으로 내림차순 정렬
    def db_so_rewards():
        print("===================== SO Reward 입력 ===================== ")
        # 'so_rewards' 컬렉션 선택
        collection = db['so_rewards']
        # 데이터 조회
        query = {'checkpoint':ObjectId(checkpoint_id)}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['reward'] = doc['reward']
            result_dic['basicReward'] = doc['basicReward']
            result_dic['blockReward'] = doc['blockReward']
            result_dic['rankReward'] = doc['rankReward']
            result_dic['leaderReward'] = doc['leaderReward']
            result_dic['memberReward'] = doc['memberReward']
            result_dic['remain'] = doc['remain']
            result_li.append(result_dic)
        print(result_li)
        
        # 리워드 값을 기준으로 내림차순 정렬
        result_li.sort(key=lambda x: int(x['reward']), reverse=True)

        # 전체 보상
        cell_list = so_cal_sh.range('J{}:J{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['basicReward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('K{}:K{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['rankReward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('L{}:L{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['blockReward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('M{}:M{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['reward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('N{}:N{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['leaderReward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('Z{}:Z{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['leaderReward']))
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('O{}:O{}'.format('8',len(result_li)+7))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['memberReward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        # 기본 보상
        cell_list = so_cal_sh.range('G{}:G{}'.format('33',len(result_li)+32))
        for i, cell in enumerate(cell_list):
            cell.value = int(result_li[i]['soId'])
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = so_cal_sh.range('H{}:H{}'.format('33',len(result_li)+32))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['basicReward'])/eth)
        so_cal_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        # 순위 보상
        cell_list = so_cal_sh.range('C{}:C{}'.format('58', len(result_li) + 57))
        top_12_rewards = [str(decimal.Decimal(result['rankReward'])/eth) for result in result_li[:12]]
        for i, cell in enumerate(cell_list[:12]):
            cell.value = top_12_rewards[i]
        so_cal_sh.update_cells(cell_list[:12], value_input_option='USER_ENTERED')
        time.sleep(2)

        # 블록 보상
        cell_list = so_cal_sh.range('C{}:C{}'.format('75', len(result_li) + 74))
        top_6_rewards = [str(decimal.Decimal(result['blockReward'])/eth) for result in result_li[:6]]
        for i, cell in enumerate(cell_list[:6]):
            cell.value = top_6_rewards[i]
        so_cal_sh.update_cells(cell_list[:6], value_input_option='USER_ENTERED')
        time.sleep(2)

        basic_reward = so_cal_sh.get_values("P28")
        rank_reward = so_cal_sh.get_values("Q28")
        block_reward = so_cal_sh.get_values("R28")
        total_reward = so_cal_sh.get_values("S28")
        leader_reward = so_cal_sh.get_values("T28")
        member_reward = so_cal_sh.get_values("U28")
        
        # SO별 기본보상 예상(QA)값과 DB상의 값 비교하여 합산한 오차 범위로 결과 입력
        if float(basic_reward[0][0]) > -0.000000001 and float(basic_reward[0][0]) < 0.000000001:
            so_cal_sh.update_acell("P29","PASS")
            result_sh.update_acell("C7","PASS")
        else:
            so_cal_sh.update_acell("P29","FAIL")
            result_sh.update_acell("C7","FAIL")

        # SO별 순위보상 예상(QA)값과 DB상의 값 비교하여 합산한 오차 범위로 결과 입력
        if float(rank_reward[0][0]) > -0.000000001 and float(rank_reward[0][0]) < 0.000000001:
            so_cal_sh.update_acell("Q29","PASS")
            result_sh.update_acell("C8","PASS")
        else:
            so_cal_sh.update_acell("Q29","FAIL")
            result_sh.update_acell("C8","FAIL")

        # SO별 블록보상 예상(QA)값과 DB상의 값 비교하여 합산한 오차 범위로 결과 입력
        if float(block_reward[0][0]) > -0.000000001 and float(block_reward[0][0]) < 0.000000001:
            so_cal_sh.update_acell("R29","PASS")
            result_sh.update_acell("C9","PASS")
        else:
            so_cal_sh.update_acell("R29","FAIL")
            result_sh.update_acell("C9","FAIL")
        
        # SO별 기본+순위+블록보상 예상(QA)값과 DB상의 값 비교하여 합산한 오차 범위로 결과 입력
        if float(total_reward[0][0]) > -0.000000001 and float(total_reward[0][0]) < 0.000000001:
            so_cal_sh.update_acell("S29","PASS")
            result_sh.update_acell("C10","PASS")
        else:
            so_cal_sh.update_acell("S29","FAIL")
            result_sh.update_acell("C10","FAIL")

        # SO별 리더보상 예상(QA)값과 DB상의 값 비교하여 합산한 오차 범위로 결과 입력
        if float(leader_reward[0][0]) > -0.000000001 and float(leader_reward[0][0]) < 0.000000001:
            so_cal_sh.update_acell("T29","PASS")
            result_sh.update_acell("C11","PASS")
        else:
            so_cal_sh.update_acell("T29","FAIL")
            result_sh.update_acell("C11","FAIL")

        # SO별 멤버보상 예상(QA)값과 DB상의 값 비교하여 합산한 오차 범위로 결과 입력
        if float(member_reward[0][0]) > -0.000000001 and float(member_reward[0][0]) < 0.000000001:
            so_cal_sh.update_acell("U29","PASS")
            result_sh.update_acell("C12","PASS")
        else:
            so_cal_sh.update_acell("U29","FAIL")
            result_sh.update_acell("C12","FAIL")

        time.sleep(10)
        print("===================== SO_ID 재정렬하여 입력 ===================== ")
        result_li.sort(key=lambda x: int(x['soId']), reverse = False)

        cell_list = user_reward_sh.range('B{}:B{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['leaderReward'])/eth)
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = user_reward_sh.range('E{}:E{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['leaderReward']))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)

        cell_list = user_reward_sh.range('C{}:C{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['memberReward'])/eth)
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(2)


    # checkpoint_id 기준 -> som_rewards 컬렉션 조회
    # 당일 SOM 별 지급되는 reward
    # Member reward만 확인 가능한 컬렉션 (som_rewards)
    # SO ID순으로 1차 정렬, ADDRESS 순으로 2차 정렬
    def db_som_rewards():
        print("===================== SOM Reward 입력 ===================== ")
        # 'som_rewards' 컬렉션 선택
        collection = db['som_rewards']
        # 데이터 조회
        query = {'checkpoint': ObjectId(checkpoint_id), 'address': {'$ne': ''}}
        query_result = collection.find(query)
        
        result_li = []
        for doc in query_result:
            result_dic = {}
            result_dic['checkpoint'] = doc['checkpoint']
            result_dic['soId'] = doc['soId']
            result_dic['address'] = doc['address']
            result_dic['reward'] = int(doc['reward'])
            result_dic['protocolId'] = doc['protocolId']
            result_dic['isCompleted'] = doc['isCompleted']
            result_li.append(result_dic)

        result_li = sorted(result_li, key=lambda x: (x['soId'], x['address']))

        cell_list = user_reward_sh.range('N{}:N{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = int(result_li[i]['soId'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('O{}:O{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str((result_li[i]['address']))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('P{}:P{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['reward'])/eth)
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('Q{}:Q{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = int(result_li[i]['protocolId'])
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AI{}:AI{}'.format('3',len(result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(result_li[i]['reward']))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')


    # som들의 위임율을 계산하여 입력.
    def qa_som_delegate_rate():
        print("===================== QA User_delegate rate 입력 ===================== ")
        # som 컬럼의 각 행 값을 so 컬럼에서 조회 -> so 컬럼에서 일치하는 인덱스 값을 저장 -> 위임율 계산 
        som_soid_col = user_reward_sh.col_values(14)
        so_soid_col = user_reward_sh.col_values(1)
        som_delegate_col = user_reward_sh.col_values(19)
        so_delegate_col = user_reward_sh.col_values(4)
                
        matched_values_li = []
        for i in range(2,len(som_soid_col)):
            matched_values = {}
            value = som_soid_col[i]
            # som 컬럼의 각 행의 id가 so 컬럼의 id에 있는지 조회
            if value in so_soid_col:
                # so_soid_col에서 일치하는 값의 인덱스 찾기
                match_index = so_soid_col.index(value)

                # som의 위임양을 변수로 저장 -> so_delegate_col에서 so,som의 id가 일치한 so의 위임양을 변수로 저장
                som_delegate_value = som_delegate_col[i]
                so_delegate_value = so_delegate_col[match_index]

                # 위임율 계산
                result = str(decimal.Decimal(som_delegate_value) / decimal.Decimal(so_delegate_value))
                print(result)

                # 계산된 값을 딕셔너리 형태로 저장한 뒤, 리스트에 저장
                matched_values[value] = result
                matched_values_li.append(matched_values)

        values = [list(d.values())[0] for d in matched_values_li]

        cell_list = user_reward_sh.range('T{}:T{}'.format('3',len(matched_values_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = values[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')


    # user_reward sheet 상에서 계산된 Delegate rate 비율과 member reward의 값을 참조하여 계산.
    def qa_som_reward():
        print("===================== QA User_reward 입력 ===================== ")
        som_soid_col = user_reward_sh.col_values(14)
        so_soid_col = user_reward_sh.col_values(1)
        som_delegaterate_col = user_reward_sh.col_values(21)
        so_member_reward_col = user_reward_sh.col_values(3)
        som_protocol_id_col = user_reward_sh.col_values(17)
        
        match_values_li = []
        flux_treasury_cal_li = []
        for i in range(2,len(som_soid_col)):
            match_values_dic = {}
            treasury_values_dic = {}
            value = som_soid_col[i]
            if value in so_soid_col:
                # so_soid_col에서 일치하는 항목의 인덱스를 찾는다.
                index = so_soid_col.index(value)

                # 해당 som의 위임율 확인
                som_delegaterate_value = som_delegaterate_col[i]
                print(som_delegaterate_value)
                
                # 인덱스를 참조해 해당하는 SO의 멤버 리워드 값 확인.
                so_member_reward_value = so_member_reward_col[index]

                # 위임율 * 멤버 리워드
                result = str(decimal.Decimal(som_delegaterate_value) * decimal.Decimal(so_member_reward_value))

                # protocol_id로 App,FLUX 구분
                som_protocol_id = som_protocol_id_col[i]
                if som_protocol_id == '1':
                    # Store the result in the dictionary with the matched value as the key
                    treasury_values_dic[value] = 0
                    flux_treasury_cal_li.append(treasury_values_dic)

                    match_values_dic[value] = result
                    match_values_li.append(match_values_dic)
                else:
                    treasury_values_dic[value] = result
                    flux_treasury_cal_li.append(treasury_values_dic)

                    match_values_dic[value] = str(decimal.Decimal(result) * decimal.Decimal(0.9))
                    match_values_li.append(match_values_dic)

        # 계산된 값 확인
        values = [list(d.values())[0] for d in match_values_li]
        treasury_values = [list(d.values())[0] for d in flux_treasury_cal_li]

        cell_list = user_reward_sh.range('W{}:W{}'.format('3',len(values)+2))
        for i, cell in enumerate(cell_list):
            cell.value = values[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AP{}:AP{}'.format('3',len(treasury_values)+2))
        for i, cell in enumerate(cell_list):
            cell.value = treasury_values[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        fail_count = user_reward_sh.get_values("Z1")

        if int(fail_count[0][0]) < 1:
            result_sh.update_acell("C13", "PASS")
        else:
            result_sh.update_acell("C13", "FAIL")

    
def get_transaction_claim(so_id, address, protocol_id):

    # 컬렉션 선택
    collection = db['transactions']

    # APP
    if str(protocol_id) == '1':
        try:
            # 쿼리문 실행
            query_results = collection.find({
                "functionName":'excuteClaimAmount', 
                "to":str(orgsmgr),
                "from": str(address),
                "eventLogs.eventName":'ClaimEvent',
                "eventLogs.params.name":'orgId',
                "eventLogs.params.value":str(so_id)
            }).sort("blockNumber", -1)
            doc = next(query_results, None)

            result = []
            if doc:
                result_dic = {}
                event_logs = doc.get('eventLogs', [])
                for event_log in event_logs:
                    if event_log.get('eventName') == 'Transfer':
                        params = event_log.get('params', [])
                        result_dic['amount'] = params[2].get('value')
                result.append(result_dic)

            return result[0]['amount']
        
        except IndexError:
            return 0

    # FLUX
    elif str(protocol_id) == '2':        

        # mongo DB에서 조회 시, kstadium address를 사용하여 조회해야 해서 address 값 변환
        print("delegator address : " + address)
        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)
        sql = f"SELECT tmember.address FROM kstadium_main.som AS tsom LEFT JOIN kstadium_main.`member` AS tmember ON tsom.member_id = tmember.id WHERE tsom.address ='{address}';"
        cursor1.execute(sql)
        rows = cursor1.fetchall()
        address = rows[0]['address']
        print("kstadium address : " + address)

        # flux는 claim, undelegate 2가지 방법으로 claim이 가능. claim과 undelegate시, block number를 비교하여 최신 block number의 데이터를 참조한다.
        # claim 최신 block number를 구하는 함수
        def claim_blocknumber_check():
            try:
                query_results = collection.find({        
                    "functionName":'claim', 
                    "to":str(flux_controller),
                    "from": str(address),
                    "eventLogs.eventName":'ClaimEvent',
                    "eventLogs.params.name":'orgId',
                    "eventLogs.params.value":str(so_id)
                }).sort("blockNumber", -1)
                doc = next(query_results, None)
                return int(doc['blockNumber'])
            except TypeError:
                pass
            except IndexError:
                pass
        
        # undelegate 최신 block number를 구하는 함수
        def undelegate_blocknubmer_check():
            try:
                query_results = collection.find({
                    "functionName":'undelegate', 
                    "to":str(flux_controller),
                    "from": str(address),
                    "eventLogs.eventName":'UnDelegate',
                    "eventLogs.params.name":'orgId',
                    "eventLogs.params.value":str(so_id)
                }).sort("blockNumber", -1)
                doc = next(query_results, None)
                return int(doc['blockNumber'])
            except TypeError:
                pass
            except IndexError:
                pass

        claim_blocknumber = claim_blocknumber_check()
        undelegate_blocknumber = undelegate_blocknubmer_check()

        result = []
        # claim, undelegate 모두 데이터가 있어야 실행되는 조건
        if claim_blocknumber and undelegate_blocknumber:
            print("claim_blocknumber : " + str(claim_blocknumber))
            print("undelegate_blocknumber : " + str(undelegate_blocknumber))
            # claim block number가 더 클 경우
            if claim_blocknumber > undelegate_blocknumber:
                query_results = collection.find({        
                    "functionName":'claim', 
                    "to":str(flux_controller),
                    "from": str(address),
                    "eventLogs.eventName":'ClaimEvent',
                    "eventLogs.params.name":'orgId',
                    "eventLogs.params.value":str(so_id)
                }).sort("blockNumber", -1)
                doc = next(query_results, None)
                
                result_dic = {}
                event_logs = doc.get('eventLogs', [])
                for event_log in event_logs:
                    if event_log.get('eventName') == 'Transfer':
                        params = event_log.get('params', [])
                        result_dic['amount'] = params[2].get('value')
                result.append(result_dic)
                print("claim, undelegate 모두 데이터가 있는 상황에서 claim 값이 참조되었음.")
                print(str(result[0]['amount']))

                return result[0]['amount']

            # undelegate block number가 더 클 경우
            else:
                query_results = collection.find({
                    "functionName":'undelegate', 
                    "to":str(flux_controller),
                    "from": str(address),
                    "eventLogs.eventName":'UnDelegate',
                    "eventLogs.params.name":'orgId',
                    "eventLogs.params.value":str(so_id)
                }).sort("blockNumber", -1)
                doc = next(query_results, None)

                result_dic = {}
                event_logs = doc.get('eventLogs', [])
                for event_log in event_logs:
                    if event_log.get('eventName') == 'UnDelegate':
                        params = event_log.get('params', [])
                        result_dic['amount'] = params[6].get('value')
                result.append(result_dic)
                print("claim, undelegate 모두 데이터가 있는 상황에서 undelegate 값이 참조되었음.")
                print(str(result[0]['amount']))

                return result[0]['amount']

        # claim 이력은 있지만 undelegate 이력이 없을 경우 실행되는 조건            
        elif claim_blocknumber and not undelegate_blocknumber:
            print("claim_blocknumber : " + str(claim_blocknumber))
            query_results = collection.find({        
                "functionName":'claim', 
                "to":str(flux_controller),
                "from": str(address),
                "eventLogs.eventName":'ClaimEvent',
                "eventLogs.params.name":'orgId',
                "eventLogs.params.value":str(so_id)
            }).sort("blockNumber", -1)
            doc = next(query_results, None)
            
            result_dic = {}
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'Transfer':
                    params = event_log.get('params', [])
                    result_dic['amount'] = params[2].get('value')
            result.append(result_dic)
            print("claim 데이터만 있는 상황.")
            print(str(result[0]['amount']))

            return result[0]['amount']

        # claim 이력은 없으며 undelegate 이력이 있을 경우 실행되는 조건            
        elif not claim_blocknumber and undelegate_blocknumber:
            print("undelegate_blocknumber : " + str(undelegate_blocknumber))
            query_results = collection.find({
                "functionName":'undelegate', 
                "to":str(flux_controller),
                "from": str(address),
                "eventLogs.eventName":'UnDelegate',
                "eventLogs.params.name":'orgId',
                "eventLogs.params.value":str(so_id)
            }).sort("blockNumber", -1)
            doc = next(query_results, None)

            result_dic = {}
            event_logs = doc.get('eventLogs', [])
            for event_log in event_logs:
                if event_log.get('eventName') == 'UnDelegate':
                    params = event_log.get('params', [])
                    result_dic['amount'] = params[6].get('value')
            result.append(result_dic)
            print("undelegate 데이터만 있는 상황.")
            print(str(result[0]['amount']))

            return result[0]['amount']

        # 그 외 
        else:
            return 0


class RDB:
    # 리워드 분배 전 RDB (kstadium_main -> som)에서 값 조회
    def som_asset_before():
        print("===================== RDB BEFORE SOM REWARD ===================== ")
        som_soid_col = user_reward_sh.col_values(14)
        som_address_col = user_reward_sh.col_values(15)
        som_protocol_id_col = user_reward_sh.col_values(17)

        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)

        soid_li = []
        address_li = []
        sop_li = []
        claim_li = []
        protocol_id_li = []
        member_id_li = []

        for i in range(2,len(som_soid_col)):
            try:
                soid = som_soid_col[i]
                address = som_address_col[i]
                protocol_id = som_protocol_id_col[i]
                # print(soid, address, protocol_id)
                sql = "SELECT so_id ,address ,sop ,claim, protocol_id, member_id FROM kstadium_main.som WHERE so_id ='{}' and address = '{}' and protocol_id='{}';".format(soid, address, protocol_id)
                cursor1.execute(sql)
                rows = cursor1.fetchall()
                
                soid_li.append(rows[0]['so_id'])
                address_li.append(rows[0]['address'])
                sop_li.append(rows[0]['sop'])
                claim_li.append(rows[0]['claim'])
                protocol_id_li.append(rows[0]['protocol_id'])
                member_id_li.append(rows[0]['member_id'])

                print(rows[0]['so_id'], rows[0]['address'],rows[0]['sop'],rows[0]['claim'],rows[0]['protocol_id'],rows[0]['member_id'])
            
            except(IndexError):
                soid_li.append(int(soid))
                address_li.append(address)
                print(soid, address)
                sop_li.append("0")
                claim_li.append("0")

                protocol_id_li.append(protocol_id)
                
                sql = "SELECT id FROM kstadium_main.`member` WHERE address = '{}';".format(address)
                cursor1.execute(sql)
                rows = cursor1.fetchall()
                member_id = rows[0]['id']
                member_id_li.append(member_id)

        # soid_li를 1차, address_li를 기준 리스트로 정렬하여, 다른 리스트들도 soid_li 졍렬에 맞게 재정렬 
        sorted_index = sorted(range(len(soid_li)), key=lambda x: (soid_li[x], address_li[x]))

        soid_li = [soid_li[i] for i in sorted_index]
        address_li = [address_li[i] for i in sorted_index]
        sop_li = [sop_li[i] for i in sorted_index]  
        claim_li = [claim_li[i] for i in sorted_index]
        protocol_id_li = [protocol_id_li[i] for i in sorted_index]
        member_id_li = [member_id_li[i] for i in sorted_index]

        cell_list = user_reward_sh.range('AA{}:AA{}'.format('3',len(soid_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = soid_li[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AB{}:AB{}'.format('3',len(address_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = address_li[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AC{}:AC{}'.format('3',len(sop_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(sop_li[i]))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AD{}:AD{}'.format('3',len(claim_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(claim_li[i]))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AG{}:AG{}'.format('3',len(protocol_id_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = protocol_id_li[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        cell_list = user_reward_sh.range('AH{}:AH{}'.format('3',len(protocol_id_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = member_id_li[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(5)


    def so_asset_before():
        print("===================== RDB BEFORE SO REWARD ===================== ")

        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)

        leader_result_li = []
        for i in range(0,19):
            sql = "SELECT id, member_id  FROM kstadium_main.so;"
            cursor1.execute(sql)
            rows = cursor1.fetchall()

            so_id = rows[i]['id']
            member_id = rows[i]['member_id']

            sql = "SELECT claim FROM kstadium_main.som WHERE protocol_id = 1 and so_id = '{}' and member_id = '{}';".format(so_id,member_id)
            cursor1.execute(sql)
            rows_ = cursor1.fetchall()
            try:
                leader_result_li.append(rows_[0]['claim'])
            except(IndexError):
                leader_result_li.append(0)

            print(so_id, rows_[0]['claim'], member_id )

        cell_list = leader_reward_sh.range('K{}:K{}'.format('3',len(leader_result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = leader_result_li[i]
        leader_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

    # 리워드 분배 후 RDB (kstadium_main -> som)에서 값 조회
    def som_asset_after():
        print("===================== RDB AFTER SOM REWARD =====================")

        som_soid_col = user_reward_sh.col_values(14)
        som_address_col = user_reward_sh.col_values(15)
        som_protocol_id_col = user_reward_sh.col_values(17)

        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)

        # 일괄 쿼리를 위한 조건들을 리스트로 생성합니다.
        conditions = ["(so_id='{}' and address='{}' and protocol_id='{}')".format(soid, addr, pid) 
                    for soid, addr, pid in zip(som_soid_col[2:], som_address_col[2:], som_protocol_id_col[2:])]

        # 일괄 쿼리를 작성합니다.
        sql = "SELECT so_id, address, sop, claim, protocol_id FROM kstadium_main.som WHERE " + " OR ".join(conditions) + ";"
        cursor1.execute(sql)
        rows = cursor1.fetchall()

        # 결과를 리스트에 저장합니다.
        soid_li = [row['so_id'] for row in rows]
        address_li = [row['address'] for row in rows]
        sop_li = [row['sop'] for row in rows]
        claim_li = [row['claim'] for row in rows]
        protocol_id_li = [row['protocol_id'] for row in rows]

        # soid_li와 address_li를 기준으로 리스트들을 정렬합니다.
        sorted_index = sorted(range(len(soid_li)), key=lambda x: (soid_li[x], address_li[x]))

        soid_li = [soid_li[i] for i in sorted_index]
        address_li = [address_li[i] for i in sorted_index]
        sop_li = [sop_li[i] for i in sorted_index]
        claim_li = [claim_li[i] for i in sorted_index]
        protocol_id_li = [protocol_id_li[i] for i in sorted_index]

        cell_list = user_reward_sh.range('AE{}:AE{}'.format('3', len(claim_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(claim_li[i]))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')
        time.sleep(5)

    def so_asset_after():
        print("===================== RDB AFTER SO REWARD =====================")
        
        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)

        print("After leader Reward")
        leader_result_li = []
        for i in range(0,19):
            sql = "SELECT id, member_id  FROM kstadium_main.so;"
            cursor1.execute(sql)
            rows = cursor1.fetchall()

            so_id = rows[i]['id']
            member_id = rows[i]['member_id']

            sql = "SELECT claim FROM kstadium_main.som WHERE protocol_id = 1 and so_id = '{}' and member_id = '{}';".format(so_id,member_id)
            cursor1.execute(sql)
            rows_ = cursor1.fetchall()
            leader_result_li.append(rows_[0]['claim'])

            print(so_id, rows_[0]['claim'], member_id )

        cell_list = leader_reward_sh.range('L{}:L{}'.format('3',len(leader_result_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = leader_result_li[i]
        leader_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')    
        

    # 리워드 분배 후 - 전을 각 케이스별 계산 후 반영
    def som_asset_cal():
        
        rdb_soid_col = user_reward_sh.col_values(27)
        rdb_address_col = user_reward_sh.col_values(28)
        rdb_reward_before_col = user_reward_sh.col_values(30)
        rdb_reward_after_col = user_reward_sh.col_values(31)
        rdb_soidaddress_after_col = user_reward_sh.col_values(45)
        mongdb_reward_col = user_reward_sh.col_values(35)
        cal_soidaddress_col = leader_reward_sh.col_values(4)
        cal_leader_reward_col = leader_reward_sh.col_values(9)
        cal_member_reward_col = leader_reward_sh.col_values(8)
        som_protocol_id_col = user_reward_sh.col_values(17)

        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)
        # AFTER - BEFORE 값 계산 후 입력
        print("===================== [SOM] RDB AFTER - BEFORE 입력 ===================== ")

        cal_value_li = []
        for i in range(2,len(rdb_reward_before_col)):
            rdb_soid = rdb_soid_col[i]
            rdb_address = rdb_address_col[i]
            before_value = rdb_reward_before_col[i] #str -> int
            after_value = rdb_reward_after_col[i] #str -> int
            mongo_value = mongdb_reward_col[i] #str
            rdb_soidaddress_value = rdb_soidaddress_after_col[i]
            protocol_id = som_protocol_id_col[i]

            # 본인 SO의 리더일 경우, 미리 리더보상을 제거한 값으로 세팅.
            if rdb_soidaddress_value in cal_soidaddress_col:
                index = cal_soidaddress_col.index(rdb_soidaddress_value)
                leader_value = cal_leader_reward_col[index]
                member_value = cal_member_reward_col[index]
                print(rdb_soid, rdb_address, leader_value, member_value)
                after_value = int(after_value) - int(leader_value)
            
            print(rdb_soid, rdb_address, before_value, after_value, mongo_value, protocol_id)
            # case1. 이전 리워드 양이 없는 상태에서 오늘 리워드를 받았고 클레임을 하지 않은 경우
            if int(before_value) == 0 and int(after_value) > 0:
                cal_value_li.append(after_value)
            
            # case2. 오늘 받은 리워드 양에서 어제 리워드 양을 차감한 값이, 오늘 지급해야할 리워드 값과 일치하는 경우
            # 클레임 안하고 누적되는 경우
            elif int(before_value) > 0  and int(after_value) > 0 and int(after_value) - int(before_value) == int(mongo_value):
                cal_value_li.append(str(int(after_value)-int(before_value)))

            # case3. 리워드 분배 전 클레임 양이 있었지만, 분배 전에 클레임 하였고, 분배 후 오늘 리워드 값을 확인한 경우
            elif int(before_value) > 0 and int(after_value) > 0 and int(after_value) == int(mongo_value):
                cal_value_li.append(str(int(after_value)))

            # case4. 이전 위임양에서 위임철회를 하여, 이전 리워드보다 오늘 리워드 양이 적을 경우
            elif int(before_value) > 0 and int(after_value) > 0 and int(after_value) - int(before_value) < 0:
                after_value_ = get_transaction_claim(rdb_soid, rdb_address, protocol_id)
                print("<< case4번 진행:" + rdb_soid + " so, " + rdb_address+" >>")
                print("after_value:", int(after_value)/int(eth))
                print("after_value_:", int(after_value_)/int(eth))
                print("before_value:", int(before_value)/int(eth))
                print("leader_value:", int(leader_value)/int(eth))                
                print("member_value:", int(member_value)/int(eth))
                # 마지막 클레임 값 - 리워드 분배 전 값
                cal_value = int(after_value_) - int(before_value)
                print("cal_value:", int(cal_value)/int(eth))   
                
                # 마지막 클레임 값 - 리워드 분배 전 값 = 리더 보상 값 -> 리더 보상 받고 클레임 하여, 현재 멤버 보상만 남아있는 상태
                if int(cal_value) == int(leader_value):
                    cal_value_li.append(str(member_value))
                # 마지막 클레임 값 - 리워드 분배 전 값 = 0 -> 현재 멤버 보상만 남아있는 상태
                elif int(cal_value) == 0:
                    cal_value_li.append(str(member_value))
                else:
                    print("cal_value " + str(cal_value))
                    cal_value_li.append(str(cal_value))
                    
            # case5. 리워드 분배 전 리워드 양은 있었지만, 오늘 리워드 값 확인 전 클레임을 한 경우
            # 이 경우, 누적 리워드 양이 며칠동안 쌓였는지 알 수 없어 멤버스냅샷과 트랜잭션 히스토리 내역을 조회해야함.
            elif int(before_value) > 0 and int(after_value) == 0:
                print("<< case5번 진행:" + rdb_soid + " so, " + rdb_address+" >>")            
                after_value_ = get_transaction_claim(rdb_soid, rdb_address, protocol_id)
                print("여기야여기!!!")
                print(after_value_)
                if int(after_value_) == int(mongo_value):
                    cal_value_li.append(str(after_value_))
                else:
                    cal_value = int(after_value_) - int(before_value)
                    cal_value_li.append(str(cal_value))

            # case 6. (리워드 분배 이전) 값 조회 전에 기존 갖고 있던 리워드를 클레임 하였고, (리워드 분배 이후) 값 조회 전 오늘 받은 리워드를 클레임 하였을 경우
            # 트랜잭션 히스토리를 통해 오늘 받은 리워드 값에 대해 클레임 이력을 조회한다.
            elif int(before_value) == 0 and int(after_value) == 0:
                print("<< case6번 진행:" + rdb_soid + " so, " + rdb_address+" >>")
                after_value_ = get_transaction_claim(rdb_soid, rdb_address, protocol_id)
                if int(after_value_) == int(mongo_value):
                    cal_value_li.append(after_value_) 
                else:
                    cal_value_li.append(0) 

            # case7. 리워드 분배되지 않은 상태
            elif int(before_value) > 0  and int(after_value) > 0 and int(after_value) == int(before_value):
                cal_value_li.append(str(000000000000))

            # case8. 위 케이스 모두 만족하지 못할 경우
            else:
                cal_value_li.append(str(999999999999))

        cell_list = user_reward_sh.range('AF{}:AF{}'.format('3',len(cal_value_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(cal_value_li[i]))
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')


    # 리워드 분배 후 - 전을 각 케이스별 계산 후 반영
    def so_asset_cal():
        
        rdb_soid_col = leader_reward_sh.col_values(1)
        rdb_address_col = leader_reward_sh.col_values(3)
        rdb_reward_before_col = leader_reward_sh.col_values(11)
        rdb_reward_after_col = leader_reward_sh.col_values(12)
        cal_leader_reward_col = leader_reward_sh.col_values(9)
        cal_member_reward_col = leader_reward_sh.col_values(8)

        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)
        # AFTER - BEFORE 값 계산 후 입력
        print("===================== [SO] RDB AFTER - BEFORE 입력 ===================== ")

        cal_value_li = []
        for i in range(2,len(rdb_reward_before_col)):
            rdb_soid = rdb_soid_col[i]
            rdb_address = rdb_address_col[i]
            before_value = rdb_reward_before_col[i] #str -> int
            after_value = rdb_reward_after_col[i] #str -> int
            member_value = cal_member_reward_col[i]
            leader_value = cal_leader_reward_col[i]
            
            print(before_value, after_value)
            # case1. 이전 리워드 양이 없는 상태에서 오늘 리워드를 받았고 클레임을 하지 않은 경우
            if int(before_value) == 0 and int(after_value) > 0:
                cal_value_li.append(str(int(after_value)-int(member_value)))
            
            # case2. 오늘 받은 리워드 양에서 어제 리워드 양을 차감한 값이, 오늘 지급해야할 리워드 값과 일치하는 경우
            # 클레임 안하고 누적되는 경우
            elif int(before_value) > 0  and int(after_value) > 0 and int(after_value) - (int(before_value) + int(member_value)) == int(leader_value):
                cal_value_li.append(str(int(leader_value)))

            # case3. 리워드 분배 전 클레임 양이 있었지만, 분배 전에 클레임 하였고, 분배 후 오늘 리워드 값을 확인한 경우
            elif int(before_value) > 0 and int(after_value) > 0 and int(after_value) - int(member_value) == int(leader_value):
                cal_value_li.append(str(int(leader_value)))

            # case4. 이전 위임양에서 위임철회를 하여, 이전 리워드보다 오늘 리워드 양이 적을 경우
            elif int(before_value) > 0 and int(after_value) > 0 and int(after_value) - int(before_value) < 0:
                print("<< case4번 진행:" + rdb_soid + " so, " + rdb_address+" >>")
                after_value_ = int(get_transaction_claim(rdb_soid, rdb_address, 1)) + int(after_value)
                print("case4번 진행:" + rdb_soid + "so" + rdb_address)
                print("after_value:", int(after_value)/int(eth))
                print("after_value_:", int(after_value_)/int(eth))
                print("before_value:", int(before_value)/int(eth))
                print("leader_value:", int(leader_value)/int(eth))
                print("member_value:", int(member_value)/int(eth))

                cal_value = int(after_value_) - (int(before_value)+int(member_value))
                cal_value_li.append(str(cal_value))
                print("cal_value:", cal_value)
                    
            # case5. 리워드 분배 전 리워드 양은 있었지만, 오늘 리워드 값 확인 전 클레임을 한 경우
            # 이 경우, 누적 리워드 양이 며칠동안 쌓였는지 알 수 없어 멤버스냅샷과 트랜잭션 히스토리 내역을 조회해야함.
            elif int(before_value) > 0 and int(after_value) == 0:
                print("<< case5번 진행:" + rdb_soid + " so, " + rdb_address+" >>")
                after_value_ = get_transaction_claim(rdb_soid, rdb_address, 1)
                cal_value = int(after_value_) - (int(before_value)+int(member_value))
                if int(after_value_)-int(member_value) == int(leader_value):
                    cal_value_li.append(str(int(after_value_))) 
                else:
                    cal_value_li.append(str(cal_value))
                
            # case 6. (리워드 분배 이전) 값 조회 전에 기존 갖고 있던 리워드를 클레임 하였고, (리워드 분배 이후) 값 조회 전 오늘 받은 리워드를 클레임 하였을 경우
            # 트랜잭션 히스토리를 통해 오늘 받은 리워드 값에 대해 클레임 이력을 조회한다.
            elif int(before_value) == 0 and int(after_value) == 0:
                print("<< case6번 진행:" + rdb_soid + " so, " + rdb_address+" >>")
                after_value_ = get_transaction_claim(rdb_soid, rdb_address, 1)
                if int(after_value_)-int(member_value) == int(leader_value):
                    cal_value_li.append(str(int(leader_value))) 
                else:
                    cal_value_li.append(0) 

            # case7. 리워드 분배되지 않은 상태
            elif int(before_value) > 0  and int(after_value) > 0 and int(after_value) == int(before_value):
                cal_value_li.append(str(000000000000))

            # case8. 위 케이스 모두 만족하지 못할 경우
            else:
                cal_value_li.append(str(999999999999))

        cell_list = leader_reward_sh.range('M{}:M{}'.format('3',len(cal_value_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = str(decimal.Decimal(cal_value_li[i]))
        leader_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')


    # qa_dashboard 시트의 user_id 입력
    def userid_check():
        print("===================== QA_DASHBOARD USER_ID 입력 =====================")
        all_memberid_col = kstadium_som_sh.col_values(1)
        
        cursor1 = rdb.cursor(pymysql.cursors.DictCursor)

        all_user_id_li = []
        for i in range(1,len(all_memberid_col)):
            memberid = all_memberid_col[i]
            sql = "SELECT tmember.user_id FROM kstadium_main.`member` as tmember left join kstadium_main.som as tsom ON tmember.id = tsom.member_id  WHERE  tmember.id= {};".format(memberid)
            cursor1.execute(sql)
            rows = cursor1.fetchall()
            user_id = rows[0]['user_id']
            all_user_id_li.append(user_id)
            print(memberid, user_id)         

        cell_list = kstadium_som_sh.range('B{}:B{}'.format('2',len(all_user_id_li)+1))
        for i, cell in enumerate(cell_list):
            cell.value = all_user_id_li[i]
        kstadium_som_sh.update_cells(cell_list, value_input_option='USER_ENTERED')


class result:
    def result_check():
        print("===================== RESULT CEHCK =====================")
        # mongo som_snapshots의 주소와 mongo som_rewards의 address가 일치하는지 확인.
        print("mongo som_snapshots ADDRESS VS mongo som_rewards ADDRESS")
        
        monogo_som_snapshots_address_col = user_reward_sh.col_values(7)
        som_address_col = user_reward_sh.col_values(15)
        reward_cal_col = user_reward_sh.col_values(25)
        rdb_cal = user_reward_sh.col_values(32)
        mongdb_reward_col = user_reward_sh.col_values(35)
        so_rdb_col = leader_reward_sh.col_values(13)
        leader_reward_col = leader_reward_sh.col_values(9)
        
        address_check_li = []
        for i in range(2,len(monogo_som_snapshots_address_col)):
            monogo_som_snapshots_address = monogo_som_snapshots_address_col[i]
            som_address = som_address_col[i]

            if monogo_som_snapshots_address == som_address:
                address_check_li.append("PASS")
            else:
                address_check_li.append("FAIL")
        
        cell_list = user_reward_sh.range('R{}:R{}'.format('3',len(address_check_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = address_check_li[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        # mongo som_rewards의 값과 예상치로 계산된 값이 일치하는지 확인
        print("mongo som_rewards REWARD VS QA REWARD")
        reward_check_li = []
        for i in range(2, len(reward_cal_col)):
            reward_cal_val = reward_cal_col[i]
            if decimal.Decimal(reward_cal_val) > -0.000000001 and decimal.Decimal(reward_cal_val) < 0.000000001:
                reward_check_li.append("PASS")
            else:
                reward_check_li.append("FAIL")

        cell_list = user_reward_sh.range('Z{}:Z{}'.format('3',len(reward_check_li)+2))
        for i, cell in enumerate(cell_list):
            cell.value = reward_check_li[i]
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        # RDB의 실분배 값이 mongo som_rewards 값과 일치하는지 확인
        print("SOM RDB VS MONGODB RESULT")
        time.sleep(3)
        result_value_li = []
        for i in range(2,len(rdb_cal)):
            rdb_cal_value = rdb_cal[i]
            mongdb_reward_col_value = mongdb_reward_col[i]

            result_value = int(rdb_cal_value) - int(mongdb_reward_col_value)
            result_value_li.append(result_value)

        result_li = []
        for i in range(0,len(result_value_li)):
            if result_value_li[i] > -1000000000 and result_value_li[i] < 1000000000: # wei 단위로 계산한 결과이며 ETH로 변환 시 0.000000001
                result_li.append("PASS")
            else:
                result_li.append("FAIL")

        cell_list = user_reward_sh.range('AL{}:AL{}'.format('3',len(result_li)+2))
        try:
            for i, cell in enumerate(cell_list):
                    cell.value = result_li[i]
        except IndexError:
            pass
        user_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        # result 시트에 입력
        # som 리워드 실분배 결과 입력
        som_reward_result = int(user_reward_sh.get_values("AL1")[0][0])
        if som_reward_result == 0:
            result_sh.update_acell("C14", "PASS")
        else:
            result_sh.update_acell("C14", "FAIL")

        # RDB의 실분배 값이 mongo so_rewards 값과 일치하는지 확인
        print("SO RDB VS MONGODB RESULT")
        time.sleep(3)
        result_value_li = []
        for i in range(2,len(so_rdb_col)):
            so_cal_reward = so_rdb_col[i]
            leader_reward = leader_reward_col[i]

            result_value = int(so_cal_reward) - int(leader_reward)
            result_value_li.append(result_value)

        cell_list = leader_reward_sh.range('N{}:N{}'.format('3',len(result_value_li)+2))
        try:
            for i, cell in enumerate(cell_list):
                    cell.value = result_value_li[i]
        except IndexError:
            pass
        leader_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        result_li = []
        for i in range(0,len(result_value_li)):
            if result_value_li[i] > -1000000000 and result_value_li[i] < 1000000000: # wei 단위로 계산한 결과이며 ETH로 변환 시 0.000000001
                result_li.append("PASS")
            else:
                result_li.append("FAIL")

        cell_list = leader_reward_sh.range('O{}:O{}'.format('3',len(result_li)+2))
        try:
            for i, cell in enumerate(cell_list):
                    cell.value = result_li[i]
        except IndexError:
            pass
        leader_reward_sh.update_cells(cell_list, value_input_option='USER_ENTERED')

        # result 시트에 입력
        # so 리워드 실분배 결과 입력
        so_reward_result = int(leader_reward_sh.get_values("O2")[0][0])
        if so_reward_result == 0:
            result_sh.update_acell("C15", "PASS")
        else:
            result_sh.update_acell("C15", "FAIL")

        return result_li

    def reward_result():
        print("===================== REWARD RESULT =====================")

        mongdb_reward_col = user_reward_sh.col_values(35)
        som_protocol_id_col = user_reward_sh.col_values(17)

        # 리워드 계산 값을 참조하여 당일 리워드 값을 확인한다.
        total_reward = 0
        app_reward = 0
        flux_reward = 0
        for i in range(2,len(mongdb_reward_col)):
            reward_val = mongdb_reward_col[i]

            total_reward += int(reward_val)

        for i in range(2,len(mongdb_reward_col)):
            reward_val = mongdb_reward_col[i]
            protocol_id_val = int(som_protocol_id_col[i])

            if protocol_id_val == 1:
                app_reward += int(reward_val)

        for i in range(2,len(mongdb_reward_col)):
            reward_val = mongdb_reward_col[i]
            protocol_id_val = int(som_protocol_id_col[i])

            if protocol_id_val == 2:
                flux_reward += int(reward_val)

        # flux_treasury_estimate 값
        collection = db['protocol_fees']
        # 데이터 조회
        query = {'checkpoint':ObjectId(checkpoint_id)}
        query_result = collection.find(query)

        result_li = []
        for doc in query_result:
            result_dic = {}
            try:
                result_dic['fee'] = doc['fee']
                result_li.append(result_dic)
            except KeyError:
                result_dic['fee'] = 0
            except IndexError:
                result_dic['fee'] = 0
        print(result_li)
        
        flux_treasury_estimate = result_dic['fee']

        # wei -> eth
        total_reward = str(decimal.Decimal(int(total_reward)/int(eth)))
        app_reward = str(decimal.Decimal(int(app_reward)/int(eth)))
        flux_reward = str(decimal.Decimal(int(flux_reward)/int(eth)))
        flux_treasury_estimate = str(round(decimal.Decimal(int(flux_treasury_estimate)/int(eth)),5))

        print("total_reward           : ", total_reward)
        print("app_reward             : ", app_reward)
        print("flux_reward            : ", flux_reward)
        print("flux_treasury_estimate : ", flux_treasury_estimate)

        reward_result_sh.update_acell("A2",datetime_)  
        reward_result_sh.update_acell("B2",total_reward)  
        reward_result_sh.update_acell("C2",app_reward)  
        reward_result_sh.update_acell("D2",flux_reward)  
        reward_result_sh.update_acell("H2",flux_treasury_estimate)  


#####################################################################################################################################################
#####################################################################################################################################################

if __name__ == '__main__':

    ###################################################################################################################
    ############################################ BEFORE_REWARD ########################################################
    ###################################################################################################################

    #==================================================================================================================
    # 각 시트들 값 초기화
    result_sh.batch_clear(['A1'])  
    result_sh.batch_clear(['C3:C15'])  
    time.sleep(3)

    snapshot_sh.batch_clear(['D3:J22'])
    time.sleep(3)

    so_cal_sh.batch_clear(['B1:B4'])
    so_cal_sh.batch_clear(['J8:O27'])
    so_cal_sh.batch_clear(['G33:H52'])
    so_cal_sh.batch_clear(['C58:C69'])  
    so_cal_sh.batch_clear(['C58:C69'])  
    so_cal_sh.batch_clear(['C75:C80'])
    so_cal_sh.batch_clear(['Z8:Z27'])
    time.sleep(3)

    user_reward_sh.batch_clear(['B3:C22'])
    user_reward_sh.batch_clear(['E3:E22'])  
    user_reward_sh.batch_clear(['F3:T'])  
    user_reward_sh.batch_clear(['W3:W'])  
    user_reward_sh.batch_clear(['Z3:AI'])
    user_reward_sh.batch_clear(['AL3:AL'])
    user_reward_sh.batch_clear(['AP3:AP'])
    user_reward_sh.batch_clear(['AS3:AS'])
    time.sleep(3)

    daily_block_sh.batch_clear(['A2:E'])
    time.sleep(3)

    kstadium_som_sh.batch_clear(['B2:B'])
    time.sleep(3)

    leader_reward_sh.batch_clear(['K3:O'])
    time.sleep(3)

    result_sh.update_acell("A1",datetime_)    

    #==================================================================================================================
    # [Mongo] checkpoint 확인
    # mongo -> checkpoint의 최신 데이터의 날짜 -1day, block_number 확인

    # blocknumber = Explorer.ex_blocknumber()
    blocknumber = Blocknumber.today_blocknumber()
    Blocknumber.yesterday_blocknumber()
    time.sleep(10)

    Db_snapshot_reward.db_checkpoint(blocknumber) # checkpoint의 시작블록을 DB 값과 비교 후 결과 입력
    time.sleep(10)

    #==================================================================================================================
    # [Explorer] reward 분배 전 treasury vault 잔액 확인
    Explorer.treasury_before_check()
    time.sleep(10)

    # ==================================================================================================================
    # [Mongo] 스크립트 진행 전날 생성된 모든 block의 block_reward 확인
    Db_snapshot_reward.db_blockreward()
    time.sleep(10)

    #==================================================================================================================
    # [Mongo] Inflation 데이터 확인
    Db_snapshot_reward.db_inflation()
    time.sleep(10)

    #==================================================================================================================
    # [Mongo] so_snapshot 데이터 확인
    Db_snapshot_reward.db_so_snapshot()
    time.sleep(10)

    #==================================================================================================================
    # [Mongo] som_snapshot 데이터 확인
    Db_snapshot_reward.db_som_snapshot()
    time.sleep(10)
    
    #==================================================================================================================
    # [Mongo] so_reward 데이터 확인
    Db_snapshot_reward.db_so_rewards()
    time.sleep(10)

    #==================================================================================================================
    # [Mongo] som_reward 데이터 확인 
    Db_snapshot_reward.db_som_rewards()
    time.sleep(10)

    #==================================================================================================================
    # [QA_calculator] QA_som들의 위임율 계산
    Db_snapshot_reward.qa_som_delegate_rate()
    time.sleep(10)

    #==================================================================================================================
    # [QA_calculator] QA_som들의 예상 리워드 계산
    Db_snapshot_reward.qa_som_reward()
    time.sleep(10)
    
    #==================================================================================================================
    # QA_som들의 예상 리워드 계산 vs som_reward
    # total_reward(app+flux 합산한 reward 값), 
    # app_reward -> app에 분배된 리워드 총합
    # flux_reward -> flux에 분배된 리워드 총합
    # flux_treasury_estimate (mongo -> protocol_fees)
    result.reward_result()
    time.sleep(10)

    #==================================================================================================================
    # [RDB] reward 분배 전 so 자산 조회
    RDB.so_asset_before()
    time.sleep(10)

    #==================================================================================================================
    # [RDB] reward 분배 전 som 자산 조회
    RDB.som_asset_before()
    time.sleep(10)


    ###################################################################################################################
    ############################################ AFTER_REWARD #########################################################
    ###################################################################################################################


    #==================================================================================================================
    # [Explorer] reward 분배 후 treasury vault 잔액 확인
    Explorer.treasury_after_check()
    time.sleep(10)

    #==================================================================================================================
    # [QA_calculator]reward 분배 후-전 treasury vault 확인
    Explorer.treasury_cal_check()
    time.sleep(10)

    #==================================================================================================================
    # [RDB] reward 분배 후 so 자산 조회
    RDB.so_asset_after()
    time.sleep(20)

    #==================================================================================================================
    # [RDB] reward 분배 후 som 자산 조회
    RDB.som_asset_after()
    time.sleep(20)

    #==================================================================================================================
    # [RDB] so_reward 분배 후-전 계산 비교
    RDB.so_asset_cal()
    time.sleep(20)

    #==================================================================================================================
    # [RDB] som_reward 분배 후-전 계산 비교
    RDB.som_asset_cal()
    time.sleep(20)

    #==================================================================================================================
    # 결과 입력
    # mongo som_snapshots의 주소와 mongo som_rewards의 address가 같은 라인에 위치하는지 확인
    # mongo som_rewards의 값과 QA에서 계산한 값이 일치하는지 확인
    # mongo som_rewards의 값과 RDB의 실분배 값이(som reward 분배 후-전) 일치하는지 확인
    # mongo so_rewards의 값과 RDB의 실분배 값이(so reward 분배 후-전) 일치하는지 확인
    result.result_check()
    time.sleep(20)

    #==================================================================================================================
    # qa_dashboard ->  kstaidum_som -> USER_ID 입력
    RDB.userid_check()
