import time
import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import ssl
import certifi


# 'YOUR_SLACK_API_TOKEN'을 실제 Slack API 토큰으로 대체하세요.
SLACK_API_TOKEN = ''

# 'YOUR_SLACK_CHANNEL'을 메시지를 게시할 Slack 채널 이름으로 대체하세요.
SLACK_CHANNEL = 'C04A3DRGX7B'
# 콘텐츠를 캡처할 URL
URL_TO_CAPTURE = ''

ssl_context = ssl.create_default_context(cafile=certifi.where())
client = WebClient(token=SLACK_API_TOKEN, ssl=ssl_context)

def send_slack_message(message):
    try:
        response = client.chat_postMessage(
            channel=SLACK_CHANNEL,
            text=message
        )
        print("Slack 메시지 전송 성공!")
    except SlackApiError as e:
        print(f"Slack 메시지 전송 실패: {e}")

def main():
    # 브라우저 설정
    options = Options()
    options.add_argument("--headless")  # 헤드리스 브라우저를 원하는 경우 이 줄의 주석을 해제하세요.
    driver = webdriver.Chrome(service=Service(ChromeDriverManager(version="114.0.5735.90").install()), options=options)

    # 창 크기 설정 (필요에 따라 값을 조정하세요)
    window_width, window_height = 1024, 768
    driver.set_window_size(window_width, window_height)

    # URL로 이동
    driver.get(URL_TO_CAPTURE)

    # 페이지 로드를 기다립니다 (페이지 로드 시간에 따라 이 지연을 조정할 수 있습니다)
    time.sleep(5)

    # id가 'compareHourlyFcast'인 div 요소를 찾습니다.
    try:
        div_element = driver.find_element(By.CSS_SELECTOR, 'div[data-template="compareHourlyFcast"]')
    except Exception as e:
        print(f"div 요소를 찾지 못했습니다: {e}")
        driver.quit()
        return

    # div 요소의 내용을 이미지로 캡처합니다.
    div_element.screenshot("div_screenshot.png")

    # div 요소의 스크린샷을 Slack으로 보냅니다.
    message = "*{}*\n오늘의 날씨 예보 및 미세먼지 수치".format(datetime.datetime.now().strftime('%Y.%m.%d %H:%M'))
    send_slack_message(message)
    try:
        response = client.files_upload(
            channels=SLACK_CHANNEL,
            file="div_screenshot.png"
        )
        print("div 요소의 스크린샷이 Slack으로 성공적으로 전송되었습니다! (날씨)")
    except SlackApiError as e:
        print(f"스크린샷을 Slack으로 전송하지 못했습니다: {e}")

    dust_url = "https://weather.naver.com/air/09680650"
    driver.get(dust_url)
    # 페이지 로드를 기다립니다 (페이지 로드 시간에 따라 이 지연을 조정할 수 있습니다)
    time.sleep(3)

    # class가 'chart_area'인 div 요소를 찾습니다.
    try:
        div_element = driver.find_element(By.CSS_SELECTOR, 'div[class="chart_area"]')
    except Exception as e:
        print(f"div 요소를 찾지 못했습니다: {e}")
        driver.quit()
        return
    div_element.screenshot("div_dust.png")

    try:
        response = client.files_upload(
            channels=SLACK_CHANNEL,
            file="div_dust.png"
        )
        print("div 요소의 스크린샷이 Slack으로 성공적으로 전송되었습니다! (미세먼지)")
    except SlackApiError as e:
        print(f"스크린샷을 Slack으로 전송하지 못했습니다: {e}")

    # 브라우저를 닫습니다.
    driver.quit()

if __name__ == "__main__":
    main()
