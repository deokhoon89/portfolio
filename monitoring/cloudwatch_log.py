# AWS ECS에 실제로 돌리는 파일 입니다.

# AWS cloudwatch의 log를 크롤링 합니다.
# 크롤링한 데이터를 구글시트에 입력합니다.

import boto3
import time
import platform
import gspread
import datetime
import pymysql
import inspect
import logging
# import log

####################################### 구글시트 설정 #######################################

sysOS = platform.system()
gs = gspread.service_account('')
sh = gs.open('').worksheet('')

file_name = inspect.getfile(inspect.currentframe()).split("/")[-1]
##########################################################################################

####################################### DB접속 설정 ########################################

prd_kstadium_rest_api = ''
prd_myid = ''
prd_mypasswd = ''
db = pymysql.connect(host=prd_kstadium_rest_api, port=3306, user=prd_myid, passwd=prd_mypasswd, db='', charset='utf8')

##########################################################################################

session = boto3.Session()

# AWS CloudWatch Logs 조회를 위한 boto3 클라이언트 생성
client = session.client('logs')

# AWS CloudWatch 로그 그룹 이름
log_group_name = ''

datetime_ = datetime.datetime.now().strftime("%Y"+"-"+"%m"+"-"+"%d")
datetimeDB_ = datetime.datetime.now().strftime("%Y"+"%m"+"%d")

# 로그 시간대 설정 (오늘)
start_time = int(time.mktime(time.strptime('{} 06:00:00'.format(datetime_), '%Y-%m-%d %H:%M:%S')) * 1000) # 특정 날짜의 ##시 ##분 ##초
end_time = int(time.mktime(time.strptime('{} 08:00:00'.format(datetime_), '%Y-%m-%d %H:%M:%S')) * 1000) # 특정 날짜의 ##시 ##분 ##초

# 로그 시간대 설정 (특정 날짜)
# start_time = int(time.mktime(time.strptime('2023-04-23 06:00:00', '%Y-%m-%d %H:%M:%S')) * 1000) # 특정 날짜의 ##시 ##분 ##초
# end_time = int(time.mktime(time.strptime('2023-04-23 08:00:00', '%Y-%m-%d %H:%M:%S')) * 1000) # 특정 날짜의 ##시 ##분 ##초


def cloudwatch_reward():

    som = []
    soid = []
    address = []
    reward = []
    
    for l in range(1,20):
        filter_pattern = '"[] SOM Reward | SO {} |"'.format(l)  # 필터링할 키워드 지정
        response = client.filter_log_events(
                    logGroupName = log_group_name,
                    startTime = start_time,
                    endTime = end_time,
                    filterPattern = filter_pattern
                )

        # AWS CloudWatch Logs 로그 스트림 조회
        message_ = []
        for event in response['events']:
            message = (event['message'])
            message_.append(message)
        
        # message 리스트를 '|' 기준으로 재리스트화
        result_list = []
        for res in message_:
            result_list.append(res.split("|"))

        # SO별 각 SOM들의 SOID, Address, reward 값을 리스트에 저장
        for j in range(len(result_list)):
            som.append(result_list[j][2])
            soid.append(result_list[j][1][3:])
            address.append(result_list[j][3][1:-1])
            reward.append(result_list[j][4][1:])

        # 구글시트에 입력
        cell_list = sh.range('A{}:A{}'.format('2',str(int(len(soid)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(soid[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = sh.range('B{}:B{}'.format('2',str(int(len(som)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(som[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = sh.range('C{}:C{}'.format('2',str(int(len(address)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(address[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = sh.range('D{}:D{}'.format('2',str(int(len(reward)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(reward[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 


############################## 다음 페이지 조회 ##############################
# 조회할 데이터 볼륨이 클 경우, 데이터를 한번씩 조회하는데 제한이 있어 여러번 조회를 해야한다. 
# nextToken 이 response 안에 담겨있고, 이 토큰이 있을 경우 계속해서 조회도록 한다.

        while 'nextToken' in response:
            current_token = response['nextToken']
            response = client.filter_log_events(
                    logGroupName = log_group_name,
                    startTime = start_time,
                    endTime = end_time,
                    filterPattern = filter_pattern,
                    nextToken = current_token
                )

            # AWS CloudWatch Logs 로그 스트림 조회
            message_ = []
            for event in response['events']:
                message = (event['message'])
                message_.append(message)
            
            # message 리스트를 '|' 기준으로 재리스트화
            result_list = []
            for res in message_:
                result_list.append(res.split("|"))

            # SO별 각 SOM들의 SOID, Address, reward 값을 리스트에 저장
            for j in range(len(result_list)):
                som.append(result_list[j][2])
                soid.append(result_list[j][1][3:])
                address.append(result_list[j][3][1:-1])
                reward.append(result_list[j][4][1:])

        # 구글시트에 입력.
        cell_list = sh.range('A{}:A{}'.format('2',str(int(len(soid)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(soid[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = sh.range('B{}:B{}'.format('2',str(int(len(som)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(som[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = sh.range('C{}:C{}'.format('2',str(int(len(address)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(address[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

        cell_list = sh.range('D{}:D{}'.format('2',str(int(len(reward)+1))))
        for i, cell in enumerate(cell_list):
            cell.value = str(reward[i])
        sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    cell_list = sh.range('M2:M21')
    for i, cell in enumerate(cell_list):
        cell.value = str(datetime_)
    sh.update_cells(cell_list, value_input_option='USER_ENTERED') 

    # 로그 레벨 설정
    logging.basicConfig(level=logging.INFO)

    # 변수 설정
    fileName = file_name
    status = "PASS"
    message = {"PRD CLOUDWATCH REWARD CHECK COMPLETE. CHECK GOOGLE SHEET. URL : "}

    # 로그 출력
    logging.info(f"{fileName} {status} {message}")

# SO voting power를 RDB에서 조회하여 구글시트에 입력합니다.
def so_votingpower():
    cursor1 = db.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT voting_power FROM kstadium_rest_api.Snapshot WHERE `date` like {} order by orgid ASC;".format(datetimeDB_)
    cursor1.execute(sql)
    rows = cursor1.fetchall()

    rows_ = []
    for i in range(len(rows)):
        rows_.append(int(rows[i]['voting_power'])/100000)

    cell_list = sh.range('L{}:L{}'.format('2',str(int(len(rows_)+1))))
    for i, cell in enumerate(cell_list):
        cell.value = str(rows_[i])
    sh.update_cells(cell_list, value_input_option='USER_ENTERED') 


# 함수 실행 구문
print("{} START AWS_PRD_reward.py".format(str(datetime_)))
cloudwatch_reward()
so_votingpower()
print("{} END AWS_PRD_reward.py".format(str(datetime_)))