#kakao.py

import requests
import json

url = 'https://kauth.kakao.com/oauth/token'
rest_api_key = ''
redirect_uri = 'https://example.com/oauth'
authorize_code = ''  # 카톡 인증용 코드 수행시마다 재발급 필요

tokens = ''
friend_id = ''

class kakao_send:
    # 최초 token들 발급하여 refresh token 저장
    def get_refresh_token():
        data = {
            'grant_type': 'authorization_code',
            'client_id': rest_api_key,
            'redirect_uri': redirect_uri,
            'code': authorize_code,
        }

        response = requests.post(url, data=data)
        tokens = response.json()

        with open('refresh_token.json', 'w') as fd:
            json.dump(tokens, fd)

    # refresh token을 이용하여 새로운 access token 발급
    def refresh_token():
        global tokens
        with open('refresh_token.json', 'r') as fd:
            token = json.load(fd)
        refresh_token = token['refresh_token']
        data = {
            'grant_type': 'refresh_token',
            'client_id': rest_api_key,
            'refresh_token': refresh_token
        }
        response = requests.post(url, data=data)
        tokens = response.json()

        with open('access_token.json', 'w') as fd:
            json.dump(tokens, fd)
        with open('access_token.json', 'r') as fd:
            ts = json.load(fd)
        tokens = ts['access_token']
        print("access_token : " + tokens)
        return tokens

    # 나에게 메시지 전송
    def send_msg(tokens, msg):
        header = {'Authorization': 'Bearer ' + tokens}
        url = 'https://kapi.kakao.com/v2/api/talk/memo/default/send'  
        post = {
            'object_type': 'text',
            'text': msg,
            'link': {
                'web_url': 'https://developers.kakao.com',
                'mobile_web_url': 'https://developers.kakao.com'
            },
            'button_title': '키워드'
        }
        data = {'template_object': json.dumps(post)}
        return requests.post(url, headers=header, data=data)

    # 친구 리스트 확인
    def friend_list():
        global friend_id
        header = {"Authorization": 'Bearer ' + tokens}
        url = "https://kapi.kakao.com/v1/api/talk/friends" #친구 정보 요청

        result = json.loads(requests.get(url, headers=header).text)

        friends_list = result.get("elements")
        friends_id = []

        # print(requests.get(url, headers=header).text)
        # print(friends_list)

        for friend in friends_list:
            friends_id.append(str(friend.get("uuid")))

        friend_id = friends_id[0]
        print("friends_id   : " + friend_id)
        return friend_id

    # 친구에게 메시지 전송
    def friend_message_send(tokens, friend_id, message, url):
        url= "https://kapi.kakao.com/v1/api/talk/friends/message/default/send"
        header = {"Authorization": 'Bearer ' + tokens}
        data={
            'receiver_uuids': '["{}"]'.format(friend_id),
            "template_object": json.dumps({
                "object_type":"text",
                "text":message,
                "link":{
                    "web_url" : url
                },
                "button_title": "예매하기"
            })
        }
        response = requests.post(url, headers=header, data=data)
        response.status_code

kakao_send.get_refresh_token()
# kakao_send.refresh_token()
# kakao_send.friend_list()
# kakao_send.friend_message_send(tokens,friend_id,message)

