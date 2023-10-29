from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import kakaotalk_send


# 로그인 정보
id = ""
pw = ""

# 크롬드라이버 경로 설정
driver_path = "/Users/deokhoonpark/workspace/chromedriver/chromedriver"

# 크롬드라이버 옵션 설정
options = webdriver.ChromeOptions()
options.add_argument("--start-maximized")

# 크롬드라이버 실행
driver = webdriver.Chrome(driver_path, options=options)

url = "https://tickets.interpark.com/goods/23006165"
# 구글 페이지 열기
driver.get(url)

# 로그인 링크 클릭
time.sleep(1)
login_link = driver.find_element(By.CSS_SELECTOR,'#gateway > div > div.gatewayUserMenu > ul > li.gatewayLogin > a')
login_link.click()

# 로그인 입력 창 안에 또 다른 창이 있었음.. 
driver.switch_to.frame(driver.find_element(By.CSS_SELECTOR, '#loginAllWrap > div.leftLoginBox > iframe'))

# 아이디 입력
time.sleep(1)
id_input = driver.find_element(By.CSS_SELECTOR,'#userId')
id_input.send_keys(id)

# 비밀번호 입력
time.sleep(1)
pw_input = driver.find_element(By.CSS_SELECTOR,'#userPwd')
pw_input.send_keys(pw)

# 로그인 버튼 선택
time.sleep(1)
login_btn = driver.find_element(By.CSS_SELECTOR,'#btn_login')
login_btn.click()

# 예매하기 버튼 선택
time.sleep(1)
ticketing_btn = driver.find_element(By.CSS_SELECTOR,'#productSide > div > div.sideBtnWrap > a.sideBtn.is-primary > span')
ticketing_btn.click()

# 새로운 창이 열림...
time.sleep(5)
# print(driver.window_handles)
driver.switch_to.window(driver.window_handles[1])

# 예매하는 화면 안에 다른 창이 있었음..
driver.switch_to.frame(driver.find_element(By.CSS_SELECTOR, '#ifrmSeat'))

# R석 확인
time.sleep(1)
seat_R = driver.find_element(By.CSS_SELECTOR,'#SeatGradeInfo > div > table > tbody > tr:nth-child(1) > td:nth-child(1) > div > strong')
seat_R = seat_R.text
seat_R_count = seat_R[3]

# S석 확인
time.sleep(1)
seat_S = driver.find_element(By.CSS_SELECTOR,'#SeatGradeInfo > div > table > tbody > tr:nth-child(2) > td:nth-child(1) > div > strong')
seat_S = seat_S.text
seat_S_count = seat_S[3]

# A석 확인
time.sleep(1)
seat_A = driver.find_element(By.CSS_SELECTOR,'#SeatGradeInfo > div > table > tbody > tr:nth-child(3) > td:nth-child(1) > div > strong')
seat_A = seat_A.text
seat_A_count = seat_A[3]

# B석 확인
time.sleep(1)
seat_B = driver.find_element(By.CSS_SELECTOR,'#SeatGradeInfo > div > table > tbody > tr:nth-child(4) > td:nth-child(1) > div > strong')
seat_B = seat_B.text
seat_B_count = seat_B[3]

# C석 확인
time.sleep(1)
seat_C = driver.find_element(By.CSS_SELECTOR,'#SeatGradeInfo > div > table > tbody > tr:nth-child(5) > td:nth-child(1) > div > strong')
seat_C = seat_C.text
seat_C_count = seat_C[3]

# 각 좌석 정보 리스트에 담기
seat_li = []
seat_li.append(seat_R)
seat_li.append(seat_S)
seat_li.append(seat_A)
seat_li.append(seat_B)
# seat_li.append(seat_C)
print("남은 좌석 : " + str(seat_li))

# R,S,A,B 중 1석 발생 시 카카오톡 메시지 전송
if int(seat_R_count) >= 1 or int(seat_S_count) >= 1 or int(seat_A_count) >= 1 or int(seat_B_count) >= 1:
    kakaotalk_send.kakao_send.friend_message_send(kakaotalk_send.tokens, kakaotalk_send.friend_id, str(seat_li), url)

# 프로그램 종료 시 브라우저 창 닫히지 않도록 대기
# input("Press Enter to quit")

# 드라이버 종료
driver.quit()
