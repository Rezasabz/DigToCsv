import csv  
from csv import writer
from email import header
from xml import dom
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
import numpy as np
import pandas as pd
import os
import glob
import re


header = ['Time','Domain', 'Source', 'Destination', 'Protocol', 'Length','TTL', 'Info']
domains = []
opcodes = []
status = []
ids = []
flags = []
query = []
answer = []
authority = []
additional = []
question_domain = []
ttl = []
question_type = []
answer_section_domain = []
answer_section_ttl = []
answer_section_ip = []
answer_section_class = []

authority_section_domain = []
authority_section_ttl = []
authority_section_class = []
authority_section_NS = []

additional_section_domain = []
additional_section_ttl = []
additional_section_ip = []
additional_section_class = []

query_time_stamp_list = []
query_time_SERVER_list = []
query_time__WHEN_list = []
query_time__MSG_SIZE_list = []



char_domain = "<<>> DiG 9.3.2rc1 <<>>"
char_header = "->>HEADER<<-"
answer_state = "Got answer:"
server_found = "(1 server found)"
connection_time_out = ";; connection timed out"
question_section = ";; QUESTION SECTION:"
answer_section = ";; ANSWER SECTION:"
authority_section = ";; AUTHORITY SECTION:"
additional_section = ";; ADDITIONAL SECTION:"
query_time = ";; Query time:"
query_time_server = ";; SERVER: "
query_time_when = ";; WHEN: "
query_time_msg_size = ";; MSG SIZE  rcvd:"

count = 0
with open('fluxor_ff.txt') as fl:
    Lines = fl.readlines()
    while count < len(Lines):
        if char_domain in Lines[count]:
            count += 1
            if connection_time_out not in Lines[count]:
                d = re.findall('(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]' , Lines[count-1])
                domains.append(d[1])

        if char_header in Lines[count]:
            opcodes.append(Lines[count].split(',')[0].split( )[3])
            status.append(Lines[count].split(',')[1].split(' ')[2])
            ids.append(re.sub('\n','',Lines[count].split(',')[2].split(' ')[2]))
            flags.append(Lines[count+1].split(';')[2].split(':')[1])
            query.append(Lines[count+1].split(',')[0].split(';')[3].split(' ')[2])
            answer.append(Lines[count+1].split(',')[1].split(' ')[2])
            authority.append(Lines[count+1].split(',')[2].split(' ')[2])
            additional.append(re.sub('\n','',Lines[count+1].split(',')[3].split(' ')[2]))

        if question_section in Lines[count]:
            q_type = re.sub('\t',' ',re.sub('\n','',re.sub('\tIN','IN',Lines[count+1].split('\t\t')[1]))).split(' ')
            question_type.append(q_type[1])

        if answer_section in Lines[count]:
            tmp_answer_section_domain = []
            tmp_answer_section_ttl = []
            tmp_answer_section_ip = []
            tmp_answer_section_class = []

            while Lines[count+1] != '\n':
                tmp_answer_section_domain.append(re.sub('\t',' ',Lines[count+1].strip().split('\t')[0]))
                tmp_answer_section_ttl.append(re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[1])
                tmp_answer_section_class.append(re.sub('\s+',' ',re.sub('\t',' ',Lines[count+1]).strip()).split(' ')[3])
                tmp_answer_section_ip.append(re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[4])
                count += 1

                if Lines[count+1] == '\n':
                    answer_section_domain.append(tmp_answer_section_domain)
                    answer_section_ttl.append(tmp_answer_section_ttl)
                    answer_section_ip.append(tmp_answer_section_ip)
                    answer_section_class.append(tmp_answer_section_class)
                    
                    tmp_answer_section_class = []
                    tmp_answer_section_ip = []
                    tmp_answer_section_ttl = []
                    tmp_answer_section_domain = []


        if authority_section in Lines[count]:
            tmp_domain = []
            tmp_ttl = []
            tmp_class = []
            tmp_NS = []
            while Lines[count+1] != '\n':
                tmp_domain.append(re.sub('\t','',Lines[count+1].strip().split('\t')[0]))
                tmp_ttl.append(re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[1])
                tmp_class.append(re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[3])
                tmp_NS.append(re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[4])

                count += 1

                if Lines[count+1] == '\n':
                    authority_section_domain.append(tmp_domain)
                    authority_section_ttl.append(tmp_ttl)
                    authority_section_class.append(tmp_class)
                    authority_section_NS.append(tmp_NS)

                    tmp_domain = []
                    tmp_ttl = []
                    tmp_class = []
                    tmp_NS = []
                    

        if additional_section in Lines[count]:
            tmp_additional_section_domain = []
            tmp_additional_section_ttl = []
            tmp_additional_section_ip = []
            tmp_additional_section_class = []

            while Lines[count+1] != '\n':
                tmp_additional_section_domain.append(re.sub('\t',' ',re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[0]))
                tmp_additional_section_ttl.append(re.sub('\t',' ',re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[1]))
                tmp_additional_section_ip.append(re.sub('\t',' ',re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[3]))
                tmp_additional_section_class.append(re.sub('\t',' ',re.sub('\s+',' ',Lines[count+1].strip()).split(' ')[4]))
                count += 1

                if Lines[count+1] == '\n':
                    additional_section_domain.append(tmp_additional_section_domain)
                    additional_section_ttl.append(tmp_additional_section_ttl)
                    additional_section_class.append(tmp_additional_section_class)
                    additional_section_ip.append(tmp_additional_section_ip)

                    tmp_additional_section_class = []
                    tmp_additional_section_ip = []
                    tmp_additional_section_ttl = []
                    tmp_additional_section_domain = []


        if query_time in Lines[count]:
            query_time_stamp_list.append(re.sub('\n', '',Lines[count].split(':')[1]))
        
        if query_time_server in Lines[count]:
            query_time_SERVER_list.append(re.sub('\n', '',Lines[count].split(':')[1]))
        
        if query_time_when in Lines[count]:
            query_time__WHEN_list.append(re.sub('\n', '',Lines[count].split(':')[1]))

        count += 1
        

dd = {'Time':'', 'Domain':domains, 'opcodes':opcodes,'status':status,'id':ids,'flags': flags,'QUERY': query, 'ANSWER': answer, 'AUTHORITY': authority, 'ADDITIONAL': additional, 'QUESTION_TYPE':question_type, 'answer_serction_domain': answer_section_domain, 'answer_section_ttl': answer_section_ttl, 'answer_section_class': answer_section_class, 'answer_section_ip': answer_section_ip, 'authority_section_domain':authority_section_domain,'authority_section_class': authority_section_class, 'authority_section_NS': authority_section_NS, 'authority_section_ttl':authority_section_ttl, 'additional_section_domain': additional_section_domain, 'additional_section_class': additional_section_class, 'additional_section_ip': additional_section_ip, 'additional_section_ttl': additional_section_ttl, 'question_type': question_type, 'query_time_stamp_list': query_time_stamp_list, 'query_time_SERVER_list': query_time_SERVER_list, 'query_time__WHEN_list': query_time__WHEN_list}
ds = pd.DataFrame(dd)
ds.to_csv('fluxor_ff.csv', index=False)
