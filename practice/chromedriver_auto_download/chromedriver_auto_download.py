import requests
import json
import os
import subprocess
import zipfile

chrome_version_url = "chrome://version/"
chrome_info_url = "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
download_folder = '/Users/medium/autotest/driver'

# 함수 실행하는 폴더 위치 확인
def check_folder_path(download_folder):
    current_folder = os.getcwd()        
    os.chdir(download_folder)    
    return current_folder

# mac 정보 확인
def check_mac_info():
    command = "uname -a"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
    split_output = output.strip().split()    
    len_split = len(split_output)
    platform = split_output[len_split-1]
    if platform == "x86_64":
        platform_ = "mac-x64"
    elif platform == "arm64":
        platform_ = 'mac-arm64'

    return platform_

# 현재 사용중인 Chrome 버전 확인
def get_chrome_version():
    try:
        command = "'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' --version"
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        version = output.strip().split()[-1]
        yeah = version.split('.')        
        find_version = f"{yeah[0]}.{yeah[1]}.{yeah[2]}"        
        return version, find_version
    except subprocess.CalledProcessError:
        return None, None
    
# Mac 정보와 Chrome 정보를 통해 다운로드 할 url 확인
def get_chromeInfo(chrome_info_url, platform_, find_version):    
    headers = {        
        'Content-Type' : 'application/x-www-form-urlencoded;charset=UTF-8'
    }
    api_url = f"{chrome_info_url}"
    response = requests.get(api_url, headers=headers)    
    res = json.loads(response.text)   
    version_li = []         
    if response.status_code == 200:
        versions = res.get("versions")                   
        for version in range(len(versions)):            
            downloads = versions[version].get('downloads')                        
            for download in downloads:    
                if download == "chromedriver":
                    chromedriver_downlaod = downloads['chromedriver']
                    for chromedriver_info in chromedriver_downlaod:
                        if chromedriver_info.get('platform') == platform_:
                            download_url = chromedriver_info.get('url')
                            download_url_split = download_url.split('/') 
                            download_version = download_url_split[6]
                            download_type = download_url_split[8][:-4]
                            download_version_split = download_version.split('.')
                            find_download_version = f"{download_version_split[0]}.{download_version_split[1]}.{download_version_split[2]}" 
                            if find_version == find_download_version:                                                            
                                version_li.append(download_url)

        len_version_li = len(version_li)        
        result_download_url = version_li[len_version_li-1]

        return result_download_url

# chromedriver 다운로드 url을 통해 driver 다운로드 (zip파일)
def get_chrome_driver(result_download_url):
    response = requests.get(result_download_url)
    if response.status_code == 200:
        with open("chromedriver.zip", "wb") as f:
            f.write(response.content)        
        return "good"
    else:        
        print(response)
        return "fail"

# 다운로드 받은 zip 파일 압축 해제
# chromedriver 경로 이동 (/Users/medium/autotest/driver)
# 불 필요 파일 삭제
# 초기 path로 변경
def driver_unzip(current_folder, download_folder):    
    with zipfile.ZipFile('chromedriver.zip', 'r') as zip_ref:        
        for file_info in zip_ref.infolist():
            file_name = file_info.filename        
            split_file_name = file_name.split('/')
        folder_name = split_file_name[0]    

    # 압축 해제  
    os.system('tar -xzvf chromedriver.zip')

    #path 저장 및 변경    
    parent_folder = f"{download_folder}/{folder_name}"        
    os.chdir(parent_folder)    
    
    # chrome driver 파일 경로 이동
    os.system(f'mv ./chromedriver {download_folder}')
    os.chdir(download_folder)
    # 불필요 파일 삭제
    os.system(f'rm -r ./{folder_name}')
    os.system(f'rm -r ./chromedriver.zip')    
    
    # 개발자 환경 세팅 적용 확인
    xattr_command = "xattr chromedriver"
    xattr_output = subprocess.check_output(xattr_command, shell=True, stderr=subprocess.STDOUT, text=True)
    try:
        if xattr_output[0] == "com.apple.quarantine":
        # 개발자 환경 세팅
            os.system('xattr -d com.apple.quarantine chromedriver')
    except:
        pass
    # 초기 path로 변경
    os.chdir(current_folder)
    
# 실행
def chromedriver_download():
    # 현재 path 저장
    current_folder = check_folder_path(download_folder)
    # mac 정보 확인
    platform_ = check_mac_info()
    # PC에 설치된 Chrome 정보 확인
    version, find_version = get_chrome_version()
    # download 할 파일 확인
    result_download_url = get_chromeInfo(chrome_info_url,platform_,find_version)
    # Chrome Driver 다운로드 (Zip File)
    download_zip= get_chrome_driver(result_download_url)
    # Unzip and 개발자 환경 설정
    driver_unzip(current_folder,download_folder)


if __name__ == '__main__':
    chromedriver_download()
