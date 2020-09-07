import time
import pycurl
import json
import certifi
from datetime import datetime, timedelta
from urllib.parse import urlencode
from io import BytesIO
import requests
from requests_oauthlib import OAuth1, OAuth1Session
from requests import models
import signal
import webbrowser

class Stream():
    def __init__(self, keys):
        self.keys = keys
        self.track = {'track': ""} # can be upgraded to handle the other API parameters
        self.url = 'https://stream.twitter.com/1.1/statuses/filter.json?' + urlencode(self.track) # will hold the url
        self.request_token = {}
        self.oauth = OAuth1Session(self.keys['consumer_key'], client_secret=self.keys['consumer_secret'])
        self.conn = None
        self.buffer = b'' # stream buffer
        self.running = True

        signal.signal(signal.SIGINT, self.ctrlC)

    def ctrlC(self, sig, frame): # to stop with ctrl+C
        self.running = False
        raise Exception()

    def authentificate_web(): # to get tokens using the web authorization (for non-dev users)
        webbrowser.open(self.get_web_auth_url(), new=2)
        pin = input()
        t = self.get_access_token(pin)
        print("Access tokens:", t) # !! ACCESS_TOKEN SHOULD BE SAVED IN A FILE AND SET IN self.keys FOR LATER USES
        return t

    def _get_oauth_url(self, endpoint):
        return 'https://self.api.twitter.com/oauth/' + endpoint

    def apply_auth(self): # using requests OAuth1 object to handle the authentification
        return OAuth1(self.keys['consumer_key'],
                      client_secret=self.keys['consumer_secret'],
                      resource_owner_key=self.keys['access_token'],
                      resource_owner_secret=self.keys['access_token_secret'],
                      decoding=None)

    def _get_request_token(self, access_type=None): # retrieve access_token
        try:
            url = self._get_oauth_url('request_token')
            if access_type:
                url += '?x_auth_access_type=%s' % access_type
            return self.oauth.fetch_request_token(url)
        except Exception as e:
            raise e

    def set_access_token(self, key, secret): # set access_token
        self.keys['access_token'] = key
        self.keys['access_token_secret'] = secret

    def get_web_auth_url(self): # get an url to authorize the app on your twitter account 
        url = self._get_oauth_url('authorize')
        self.request_token = self._get_request_token()
        return self.oauth.authorization_url(url)

    def get_access_token(self, verifier=None): # get stored access tokens
        url = self._get_oauth_url('access_token')
        self.oauth = OAuth1Session(self.keys['consumer_key'], client_secret=self.keys['consumer_secret'], resource_owner_key=self.request_token['oauth_token'], resource_owner_secret=self.request_token['oauth_token_secret'], verifier=verifier)
        resp = self.oauth.fetch_access_token(url)
        self.keys['access_token'] = resp['oauth_token']
        self.keys['access_token_secret'] = resp['oauth_token_secret']
        return self.keys['access_token'], self.keys['access_token_secret']

    def verify_credentials(self): # verify if everything is alright
        r = requests.get(url="https://api.twitter.com/1.1/account/verify_credentials.json", auth=self.apply_auth())
        data = json.loads(r.content)
        print("Logged as", data.get('screen_name', ''))
        return 'screen_name' in data

    def get_oauth_header(self): # used by pyurl, get the Authorization header to access the stream
        r = models.PreparedRequest()
        r.prepare(method="POST", url=self.url, params=self.track)
        o = self.apply_auth()
        o(r)
        return r.headers['Authorization']

    def start(self, track : list): # main loop
        self.track['track'] = ",".join(track) # update tracked
        self.url = 'https://stream.twitter.com/1.1/statuses/filter.json?' + urlencode(self.track) # and url
        while self.running:
            if self.conn: # stop connection if it exists
                self.conn.close()
                self.buffer = b''

            self.conn = pycurl.Curl()
            self.conn.setopt(pycurl.SSL_VERIFYPEER, 1)
            self.conn.setopt(pycurl.SSL_VERIFYHOST, 2)
            self.conn.setopt(pycurl.CAINFO, certifi.where()) # needed for SSL
            self.conn.setopt(pycurl.URL, self.url)
            self.conn.setopt(pycurl.POSTFIELDS, urlencode(self.track)) # POST parameters
            self.conn.setopt(pycurl.VERBOSE, 1) # can be removed (used for DEBUG)
            self.conn.setopt(pycurl.HTTPHEADER, ['Host: stream.twitter.com', 'Authorization: %s' % self.get_oauth_header()]) # header
            self.conn.setopt(pycurl.WRITEFUNCTION, self.handle_tweet) # write function callback

            timer_network_error = 0.25
            timer_http_error = 5
            timer_rate_limit = 60
            try:
                self.conn.perform() # get the stream going
            except Exception as e:
                print('Network error:', self.conn.errstr())
                print('Waiting', timer_network_error, 'seconds before trying again')
                time.sleep(timer_network_error)
                timer_network_error = min(timer_network_error + 1, 16) # increase timer
                continue
            # HTTP Error Handling
            sc = self.conn.getinfo(pycurl.HTTP_CODE)
            if sc == 420: # 420 is Twitter Rate Limit
                print('Rate limit, waiting',timer_rate_limit,'seconds')
                time.sleep(timer_rate_limit)
                timer_rate_limit *= 2
                # NOTE: it's possible to get the time to wait from twitter itself, it might be better to use it
            else:
                # Other HTTP error
                print('HTTP error', sc, ',', self.conn.errstr())
                print('Waiting ',timer_http_error ,' seconds')
                time.sleep(timer_http_error)
                timer_http_error = min(timer_http_error * 2, 320)

    def handle_tweet(self, data): # write callback
        self.buffer += data
        if data.endswith(b'\r\n') and self.buffer.strip():
            message = json.loads(self.buffer)
            self.buffer = b''
            msg = ''
            if message.get('limit'): print('Missed', message['limit'].get('track'),'tweets because of the rate limit')
            elif message.get('disconnect'):  raise Exception('Disconnection:' + str(message['disconnect'].get('reason')))
            elif message.get('warning'): print('Warning:', message['warning'].get('message'))
            else:
                print(message.get('text')) # print tweet
                # ...
                # Do stuff with the tweet here
                # ...

s = Stream({'consumer_key': "",
            'consumer_secret': "",
            'access_token': "",
            'access_token_secret': ""})
if not s.verify_credentials():
    print("failed to authentificate")
else:
    s.start(["cat", "dog"]) # stuff to search