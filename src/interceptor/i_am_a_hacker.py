import json, time, urllib2
import client
from client import JMessageClient

class interceptor:
    __server_url = 'http://127.0.0.1/'
    __intercepted_msg = ''
    __intercepted_user = ''
    __sender_id = ''
    __user = ''
    __j_client = object

    def __init__(self):
        pass

    def part_1(self,intercept_user):
        msg = self.intercept_msg(intercept_user)
        message_id, sender_id, sent_time, message = self.process_msg(msg)
        print '==============PART 1==============='
        print 'Intercepted msg from', sender_id, 'to', intercept_user
        print 'Message ID:', message_id
        print 'From user:', sender_id
        print 'Sent time:', sent_time
        print 'encrypted message:', message
        print '==================================='
        print '\n\n'
        self.set_sender_id(sender_id)
        self.set_intercepted_msg(message)
        self.set_intercepted_user(intercept_user)

    def part_2(self):
        sender_id = self.get_sender_id()
        l = len(sender_id)
        username = self.gen_username(l)
        self.set_user(username)
        print '==============PART 2==============='
        msg = self.get_intercepted_msg()
        print 'original message:', msg
        print 'original message len:', len(msg)

        self.set_j_client(JMessageClient(self.get_server_url(), self.get_user()))
        mauled_msg = self.maul_msg(msg)
        print 'modified message:', mauled_msg
        print 'modified message len:', len(mauled_msg)

        result = self.get_j_client().send_message_for_lab3(self.get_intercepted_user(), mauled_msg, self.get_server_url())
        msg_from_hacked_user = self.intercept_msg(username)
        self.process_result_for_part2(msg_from_hacked_user)
        print '==================================='

    def process_result_for_part2(self,msg):
        m_id, s_id, s_time, message = self.process_msg(msg)
        message = self.get_j_client().get_j_msg_crypto().decrypt(message,s_id)
        print 'Get reply message from:',s_id
        print 'Message ID:', m_id
        print 'From user:', s_id
        print 'Sent time:', s_time
        print 'message:', message

    def process_msg(self, msg):
        sent_time = ''
        message_id = ''
        message = ''
        sender_id = ''
        for m in msg:
            sent_time = m['sentTime']
            message_id = m['messageID']
            message = m['message']
            sender_id = m['senderID']
            sent_time = self.adjust_time_form(sent_time)

        return message_id, sender_id, sent_time, message

    def obtain_msg(self, userid):
        regi_url = self.__server_url + '/getMessages/' + userid
        request = urllib2.Request(regi_url)
        request.add_header('Accept', 'application/json')
        response = urllib2.urlopen(request)
        msg = response.read()
        msg = json.loads(msg)
        msg_num = msg['numMessages']
        text = msg['messages']
        return msg_num, text

    def intercept_msg(self, userid):
        while True:
            msg_num, msg = self.obtain_msg(userid)
            if msg_num != 0 :
                return msg

    def maul_msg(self, msg):

        return self.get_j_client().maul_msg_for_lab3_part2(msg, self.get_sender_id() ,self.get_user())



    def adjust_time_form(self, oldtime):
        return time.ctime(oldtime)

    def gen_username(self,len):
        username = ''
        for i in range(0, len):
            username += 'g'

        return username

    def set_server_url(self,url):
        self.__server_url = url

    def get_server_url(self):
        return self.__server_url

    def set_intercepted_msg(self,msg):
        self.__intercepted_msg = msg

    def get_intercepted_msg(self):
        return self.__intercepted_msg

    def set_intercepted_user(self, user):
        self.__intercepted_user = user

    def get_intercepted_user(self):
        return self.__intercepted_user

    def set_user(self, user):
        self.__user = user

    def get_user(self):
        return self.__user

    def set_j_client(self, j_client):
        self.__j_client = j_client

    def get_j_client(self):
        return self.__j_client

    def set_sender_id(self,useried):
        self.__sender_id = useried

    def get_sender_id(self):
        return self.__sender_id


inter = interceptor()
inter.part_1('alice')
inter.part_2()
# a = '1111'
# a = unicode(a)
# b = '9999'
# print inter.xor(a,b)
