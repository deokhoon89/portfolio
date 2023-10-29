import requests
import json
from bs4 import BeautifulSoup
import bs4
import openai
import re
import random


def popular_keyword():
    # 웹사이트 URL
    # 아래 웹사이트에서 오늘날짜의 1위인 키워드를 검색한다.
    url = "https://datalab.naver.com/"
    res = requests.get(url)
    bs = bs4.BeautifulSoup(res.text, 'lxml')
    keywords_elements = bs.select('.keyword_rank .list .title')
    
    # 화면 내 보이는 키워드를 모두 리스트화
    keyword = [element.text for element in keywords_elements]

    # 리스트 중 임의의 아이템을 랜덤으로 키워드 변수에 저장
    keyword = random.choice(keyword)

    return keyword

def search_chatgpt(keyword):

    # openai key는 'https://platform.openai.com/account/billing/overview' 사이트에서 카드 결제를 등록해야만 사용 가능합니다.
    # api 호출 시, 검색 결과에 대한 token 값으로 과금이 청구되는데, 얼마 안하니 걱정 놉!
    # query 변수는 가능하면 저 상태로 유지하는게 좋음. 만약 변경하고 싶다면 query 검색 결과를  '제목:', '내용:','해시태크:' 로 나누어서 검색결과를 달라고 해야함.

    # API key 값 입력
    # 'https://platform.openai.com/account/api-keys' 에서 확인.
    openai.api_key = ''

    # model은 여러가지가 있지만 gpt-3.5-turbo가 가성비,성능 좋음
    model = "gpt-3.5-turbo"

    # 질문 작성하기
    query = f"{keyword}를 주제로 첫 줄에는 '제목:' 형식으로 마케터 관점에서의 내용에 부합하는 제목, 다음줄부터는 '내용:' 형식으로 주제의 가장 인기있는 브랜드, 그 브랜드에서 인기있는 모델 소개, 그리고 해당 모델을 착용한 연예이 있는지와, 또 인기있는 모델을 구매할 수 있는 여러 사이트들과 링크에 대한 블로그 글을 1000자 이상으로 작성해줘. 가장 마지막 줄에는 '해시태그: #' 형식으로 20개 이상 작성해줘."
    
    # 메시지 설정하기
    messages = [
            {"role": "system", "content": "You are a helpful assistant and marketer."}, # 챗지피티 가스라이팅 "넌..내게 있어.. 마케터고..도움을 주는 애야.."
            {"role": "user", "content": query}
    ]

    # ChatGPT API 호출하기
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages
    )
    
    # 검색 결과 텍스트 가져와서 answer 변수에 담기
    answer = response['choices'][0]['message']['content']
    
    return answer  

def tistory_auth():

    # 티스토리 API 화면에서 확인 가능
    tistory_client_id = ''
    tistory_secret_key = ''
    
    # 본인의 블로그 주소
    tistory_redirect_uri = ''  #ex) https://deokkku.tistory.com/

    # code_url에서 인증을 통해 code 확인
    code_url = "https://www.tistory.com/oauth/authorize?client_id={}&redirect_uri={}&response_type=code".format(tistory_client_id,tistory_redirect_uri)
    print(code_url)

    # code_url에서을 통해 얻은 코드값 입력
    code = ''

    # code 값을 통해 access_toke_url에 접속해 access_token 확인
    access_toke_url = "https://www.tistory.com/oauth/access_token?client_id={}&client_secret={}&redirect_uri={}&code={}&grant_type=authorization_code".format(tistory_client_id,tistory_secret_key,tistory_redirect_uri, code)
    
    print(access_toke_url)

def tistory_category():

    blogName = "" #ex) deokkku

    def list_of_Category():
        url = "https://www.tistory.com/apis/category/list"

        params = {
            'access_token': tistory_access_token,
            'output': 'json', # json, xml 두 가지 형식 지원
            'blogName': blogName   # ().tistory.com 또는 블로그 주소 전체
        }
        
        res = requests.get(url, params=params)

        if res.status_code == 200:
            res_json = res.json()
            print(res_json)

    if __name__ == '__main__':

        list_of_Category()

def tistory_write(title_, content_, hashtag_):
    # API 엔드포인트 설정
    
    # 티스토리 API endpoiont -> 수정하지 않아도 됨.
    endpoint = 'https://www.tistory.com/apis/post/write'

    # 카테고리 변수 생성 및 ID 입력
    # 카테고리는 tistory_category 함수 실행하면 확인할 수 있음.
    shopping = 1164161 # 예시임. 본인의 블로그에서 카테고리 ID를 찾아야함.

    # 요청 매개변수 설정
    output_type = 'json'
    blog_name = 'deokkku'  # xxxx.tistory.com에서 "xxxx" 부분
    title = title_ # 제목
    content = content_ # 내용
    visibility = 2  # 0: 비공개, 1: 보호, 2: 발행
    category_id = shopping  # 카테고리 ID -> tistory_category 함수에서 확인 가능
    published = 'false'  # 공개 예약 여부
    slogan = '' # 글 슬로건
    tag = hashtag_ # 태그 (선택 사항)
    accept_comment = 1  # 댓글 허용 여부
    password = ''  # 글 비밀번호 (선택 사항)

    # 글 작성 요청
    params = {
        'access_token': tistory_access_token,
        'output': output_type,
        'blogName': blog_name,
        'title': title, 
        'content': content,
        'visibility': visibility,
        'category': category_id,
        'published': published,
        'slogan': slogan,
        'tag': tag,
        'acceptComment': accept_comment,
        'password': password
    }

    response = requests.post(endpoint, params=params)

def format_content(content):
    # 문단을 <p> 태그로 감싸기
    paragraphs = content.split('\n')
    formatted_paragraphs = [f"<p>{p}</p>" for p in paragraphs if p.strip()]
    
    # 각 문단 내에서 문장을 <span> 태그로 감싸기
    for i in range(len(formatted_paragraphs)):
        sentences = formatted_paragraphs[i].split('.')
        formatted_sentences = [f"<span>{s}</span>" for s in sentences if s.strip()]
        formatted_paragraphs[i] = ''.join(formatted_sentences)

    return '\n'.join(formatted_paragraphs)



########################################### 실행 ###########################################

# tistory access_token
# 토큰 얻는 방법은 'https://news.mkttalk.com/entry/tistory-api-access-token-generator' 참조
# 토큰은 한달 동안 유지됨.
# 최초 1회는 위 블로그에서 전달 받고, 이후에는 tistory_auth 실행해서 확인하면 됨.
tistory_access_token = ''

# 특정 사이트에서 키워드 검색 값 반환
keyword = popular_keyword()

# 챗지피티로 키워드 검색
chatgpt_answer = search_chatgpt(keyword)

# 챗지피티 검색 결과를 '제목:', '내용:', '해시태그:' 로 나누어 변수에 각각 저장
sections = re.split('(제목:|내용:|해시태그:)', chatgpt_answer)
# 각 섹션을 해당하는 변수에 할당합니다.
title = sections[sections.index('제목:') + 1].strip()
content = sections[sections.index('내용:') + 1].strip()
hashtags = sections[sections.index('해시태그:') + 1].strip()

# '내용:' 텍스트를 html 태그를 입힘. 
#  기존에는 맞춤법과 문단이 적용되지 않아 저품질 먹을 수 있음.
formatted_content = format_content(content)

# 티스토리 글 등록
tistory_write(title, formatted_content, hashtags)

# 티스토리 카테고리 ID 확인 함수
# tistory_category()