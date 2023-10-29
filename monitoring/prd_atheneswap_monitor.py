import requests
from datetime import datetime
import re
import decimal
import platform
import gspread

env = 'prd'
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
dex_sh = gs.open(sheet_file).worksheet("dex")

today_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

wei = 1000000000000000000

slack_token = ""
channel = ""

##############################################################
##                 Atheneswap account info                  ##
##############################################################
nst_contract = ""
inksta_contract = ""
ksusdt_contract = ""
kseth_contract = ""
loui_contract = ""
router_contract = ""
mc_contract = ""
nst_pair = ""
inksta_pair = ""
loui_pair = ""
kseth_pair = ""
ksusdt_pair = ""
loui_pool = ""
fee_treasury = ""
reward_treasury = ""
treasury = ""
dev = ""
ecoSystem = ""
burn = ""
fee_to = ""

##############################################################
##                   Atheneswap URI info                    ##
##############################################################
reserve_url = ""
total_url = ""
contract_balacnce = ""
pair_list_url = ''

########################################    get_feeTo_balane    #######################################
## 주소를 통해 Pair 풀 컨트랙트의 feeTo 계정에 추가된 LP 조회                                                   ##
## return = ksta_nst_feeto, ksta_inksta_feeto, ksta_loui_feeto, ksta_kseth_feeto, ksta_ksusdt_feeto  ##
########################################    get_feeTo_balane    #######################################
def get_feeTo_balance ():
    print ("#############  Fee To 계정 Balance 조회  #############")
    feeto_list = {
        "KSTA-NST" : ""+nst_pair+""+fee_to,
        "KSTA-inKSTA" : ""+loui_pair+""+fee_to,
        "KSTA-LOUI" : ""+ksusdt_pair+""+fee_to,
        "KSTA-ksETH" : ""+kseth_pair+""+fee_to,
        "KSTA-ksUSDT" : ""+inksta_pair+""+fee_to
    }

    for key, value in feeto_list.items(): 
        if "KSTA-NST" in key :
            response = requests.get(value)
            data = response.text
            search_result = [data]
            pattern = r'"name":\s*"([^"]+)",\s*"balance":\s*"([^"]+)"'
            matches = re.search(pattern, search_result[0])
            if matches: # feeto_name = matches.group(1)
                feeto_balance = matches.group(2)
                ksta_nst_feeto = f"{key} feeTo : {feeto_balance}"
                print (ksta_nst_feeto)
        if "KSTA-inKSTA" in key :
            response = requests.get(value)
            data = response.text
            search_result = [data]
            pattern = r'"name":\s*"([^"]+)",\s*"balance":\s*"([^"]+)"'
            matches = re.search(pattern, search_result[0])
            if matches:
                feeto_balance = matches.group(2)
                ksta_inksta_feeto = f"{key} feeTo : {feeto_balance}"
                print (ksta_inksta_feeto)
        if "KSTA-LOUI" in key :
            response = requests.get(value)
            data = response.text
            search_result = [data]
            pattern = r'"name":\s*"([^"]+)",\s*"balance":\s*"([^"]+)"'
            matches = re.search(pattern, search_result[0])
            if matches:
                feeto_balance = matches.group(2)
                ksta_loui_feeto = f"{key} feeTo : {feeto_balance}"
                print (ksta_loui_feeto)
        if "KSTA-ksETH" in key :
            response = requests.get(value)
            data = response.text
            search_result = [data]
            pattern = r'"name":\s*"([^"]+)",\s*"balance":\s*"([^"]+)"'
            matches = re.search(pattern, search_result[0])
            if matches:
                feeto_balance = matches.group(2)
                ksta_kseth_feeto = f"{key} feeTo : {feeto_balance}"
                print (ksta_kseth_feeto)
        if "KSTA-ksUSDT" in key :
            response = requests.get(value)
            data = response.text
            search_result = [data]
            pattern = r'"name":\s*"([^"]+)",\s*"balance":\s*"([^"]+)"'
            matches = re.search(pattern, search_result[0])
            if matches:
                feeto_balance = matches.group(2)
                ksta_ksusdt_feeto = f"{key} feeTo : {feeto_balance}"
                print (ksta_ksusdt_feeto,'\n')
 
    return ksta_nst_feeto, ksta_inksta_feeto, ksta_loui_feeto, ksta_kseth_feeto, ksta_ksusdt_feeto

####################################    get_reserve_total_balance    ##################################
## reserve, total supply api 를 조회                                                                   ##
## return = result (딕셔너리 형태로 pair reserve, total supply 리턴)                                      ##
####################################    get_reserve_total_balance    ##################################
def get_reserve_total_balance ():
    # print ("#############  유동성 reserve, total Supply 조회  #############")
    token_list = ["NST", "ksUSDT", "LOUI", "ksETH", "inKSTA", "DLT"]
    result = {}
    result_li = []
    result_kstarate_li = []
    result_totalsupply_li = []
    for i in range(len(token_list)):
        result_kstarate_dic = {}
        result_totalsupply_dic = {}

        reserve_response = requests.get(reserve_url+token_list[i])
        total_response = requests.get(total_url+token_list[i])
        reserve_data = reserve_response.json()
        total_data = total_response.json()
        dict_list = [reserve_data, total_data]
        reserveA = float(dict_list[0]['reserveA'])
        reserveB = float(dict_list[0]['reserveB'])
        totalsupply = float(dict_list[1])
        
        result_li.append(reserveA)
        result_li.append(reserveB)
        result_li.append(totalsupply)
        
        result[token_list[i]] = result_li
        result_li = []

        ksta_rate = str(round(decimal.Decimal(reserveB/reserveA),5))
        result_kstarate_dic[token_list[i]] = ksta_rate
        result_kstarate_li.append(result_kstarate_dic)

        totalsupply_ = str(round(decimal.Decimal(totalsupply/wei),5))
        result_totalsupply_dic[token_list[i]] = totalsupply_
        result_totalsupply_li.append(result_totalsupply_dic)
        
    return result_kstarate_li, result_totalsupply_li

#########################################    get_pair_balance    #########################################
## 각 풀에 스테이킹 되어 있는 Pooled 수량을 조회                                                                 ##
## return = Not yet...                                                                                  ##
#########################################    get_pair_balance    #########################################
def get_pair_balance ():
    contract_list = {
        "KSTA-NST" : "",
        "KSTA-inKSTA" : "",
        "KSTA-LOUI" : "",
        "KSTA-ksETH" : "",
        "KSTA-ksUSDT" : "",
        "KSTA-DLT" : ""
        }
    for key, value in contract_list.items():
        print ("\n#############",key,"Pair 풀 Balance #############")
        if "KSTA-NST" in key:
            response = requests.get(contract_balacnce + value)
            data = response.json()
            for j in range(len(data)) :
                if data[j]["balance"] >= 0.1 :
                    token_name = data[j]["token_name"]
                    token_balance = data[j]["balance"]
                    print (token_name, token_balance, float(token_balance)/wei, token_name)
                else :
                    pass
        if "KSTA-LOUI" in key:
            response = requests.get(contract_balacnce + value)
            data = response.json()
            for j in range(len(data)) :
                if data[j]["balance"] >= 0.1 :
                    token_name = data[j]["token_name"]
                    token_balance = data[j]["balance"]
                    print (token_name, token_balance, float(token_balance)/wei, token_name)
                else :
                    pass
        if "KSTA-ksUSDT" in key:
            response = requests.get(contract_balacnce + value)
            data = response.json()
            for j in range(len(data)) :
                if data[j]["balance"] >= 0.1 :
                    token_name = data[j]["token_name"]
                    token_balance = data[j]["balance"]
                    print (token_name, token_balance, float(token_balance)/wei, token_name)
                else :
                    pass
        if "KSTA-ksETH" in key:
            response = requests.get(contract_balacnce + value)
            data = response.json()
            for j in range(len(data)) :
                if data[j]["balance"] >= 0.1 :
                    token_name = data[j]["token_name"]
                    token_balance = data[j]["balance"]
                    print (token_name, token_balance, float(token_balance)/wei, token_name)
                else :
                    pass
        if "KSTA-inKSTA" in key:
            response = requests.get(contract_balacnce + value)
            data = response.json()
            for j in range(len(data)) :
                if data[j]["balance"] >= 0.1 :
                    token_name = data[j]["token_name"]
                    token_balance = data[j]["balance"]
                    print (token_name, token_balance, float(token_balance)/wei, token_name)
                else :
                    pass

        if "KSTA-DLT" in key:
            response = requests.get(contract_balacnce + value)
            data = response.json()
            for j in range(len(data)) :
                if data[j]["balance"] >= 0.1 :
                    token_name = data[j]["token_name"]
                    token_balance = data[j]["balance"]
                    print (token_name, token_balance, float(token_balance)/wei, token_name)
                else :
                    pass

#####################################    get_pair_staked_balance    #####################################
## 각 풀의 총 USD를 이용하여, 풀의 예상 Total Staked를 계산                                                     ##
## return = Not yet...                                                                                 ##
#####################################    get_pair_staked_balance    #####################################
def get_pair_staked_balance():
    print ("\n############# Pair 풀 Estimates LP Balance #############")
    token_list = ["NST", "ksUSDT", "LOUI", "ksETH", "inKSTA"]
    for i in range(len(token_list)):
        reserve_response = requests.get(reserve_url+token_list[i])
        total_response = requests.get(total_url+token_list[i])
        reserve_data = reserve_response.json()
        total_data = total_response.json()
        dict_list = [reserve_data, total_data]
        reserveA = float(dict_list[0]['reserveA'])
        reserveB = float(dict_list[0]['reserveB'])
        totalsupply = float(dict_list[1])
        
        response = requests.get(pair_list_url)
        data = response.json()
    
        for item in data :
            if item.get('token_b_name') == token_list[i]:
                total_liquidity_usd = item.get('total_liquidity_usd')
                liquidity_usd = float(total_liquidity_usd / 10000000)
                token_B_usd = 1 * ((reserveA * wei) / (reserveB * wei))
                total_lp_usd = ((reserveA * 1) / wei)+((reserveB * token_B_usd) / wei)
                lp_ratio = liquidity_usd/total_lp_usd
                lp_staked = lp_ratio * totalsupply
                print ("Estimates KSTA-"+token_list[i]+" Staked : ", lp_staked/wei, "Total USD $:", liquidity_usd)
                
    print('')


########################################    get_single_balance    ######################################
##  주소를 통해 Loui 풀 컨트랙트의 현재 Stake 조회                                                             ##
## return = single_name, single_balance                                                               ##
#########################################   get_single_balance    ######################################
def get_single_balance ():
    print ("#############  싱글 풀 Total Staked 수량 조회  #############")
    total_staked_url = ""+loui_contract+""+loui_pool
    response = requests.get(total_staked_url)
    data = response.text
    search_result = [data]
    pattern = r'"name":\s*"([^"]+)",\s*"balance":\s*"([^"]+)"'
    matches = re.search(pattern, search_result[0])
    if matches:
        single_name = matches.group(1)
        single_balance = matches.group(2)
        print ("Loui Pool Staked",single_balance,'\n')
    
    return single_name, single_balance


########################################    get_single_balance    ######################################
## Binance 에서 ETH 가격을 조회해 KSTA-ETH 풀에서 KSTA 실제 예상가를 계산                                        ##
## Coinmarketcap (CMC)에서 Uniswap 에서의 현재 KSTA 가격을 조회                                              ##
## Uniswap - Atheneswap 의 차로 현재 KSTA 가격의 괴리감 확인                                                 ##
#########################################   get_single_balance    ######################################
def get_cmc_ksta_price():
    cmc_url = ''
    cmc_response = requests.get(cmc_url)
    cmc_data = cmc_response.json()
    cmc_ksta_price = cmc_data['data'][1]['priceUsd']
    
    return cmc_ksta_price

def get_cmc_eth_price():
    cmc_url = ''
    cmc_response = requests.get(cmc_url)
    cmc_data = cmc_response.json()
    cmc_eth_price = cmc_data['data']['quote'][0]['price']
    
    return cmc_eth_price

def get_pool_info():  # reserve, totalSupply 조회
    reserve_url = ''
    totalsupply_url = ''
    
    reserve_response = requests.get(reserve_url)
    reserve_data = reserve_response.json()
    total_response = requests.get(totalsupply_url)
    total_data = total_response.json()
    
    reserve_a = float(reserve_data['reserveA'])
    reserve_b = float(reserve_data['reserveB'])
    totalsupply = float(total_data)
    
    return (reserve_a, reserve_b, totalsupply)
           
def get_bnb_eth_price(): # return = eth_price,  # binance price 조회
    binance_api_url = ''
    params = {'symbol': 'ETHUSDT'}
    api_response = requests.get(binance_api_url, params=params)
    api_data = api_response.json()
    eth_price = float(api_data['price'])
    return (eth_price)


# 슬랙 봇
def send_slack_message (message): 
    requests.post("https://slack.com/api/chat.postMessage",
        headers={"Authorization": "Bearer "+slack_token},
        data={"channel": channel,"text": message
            })



# 실행구문
reserve = get_reserve_total_balance()[0]
totalsupply = get_reserve_total_balance()[1]

token_list = ["NST", "ksUSDT", "LOUI", "ksETH", "inKSTA" , "DLT"]

dex_sh.update_acell("A2", today_date)

reserve_li = []
for i in range(0, len(token_list)):
    reserve_value = reserve[i][token_list[i]]
    reserve_li.append(reserve_value)

reserve_col = 'B'
for i in range(0,len(reserve_li)):
    dex_sh.update_acell("{}2".format(reserve_col),reserve_li[i])
    reserve_col = chr(ord(reserve_col) + 1)

totalsupply_li = []
for i in range(0, len(token_list)):
    totalsupply_value = totalsupply[i][token_list[i]]
    totalsupply_li.append(totalsupply_value)

totalsupply_col = 'H'
for i in range(0,len(totalsupply_li)):
    dex_sh.update_acell("{}2".format(totalsupply_col),totalsupply_li[i])
    totalsupply_col = chr(ord(totalsupply_col) + 1)

dex_sh.insert_row(['', '', '', '', '', '', ''],2)  # 행추가