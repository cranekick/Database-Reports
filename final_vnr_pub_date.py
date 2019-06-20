#!/usr/bin/env python3


import io
import csv
import pandas as pd
import sqlalchemy
import mysql.connector
import re
import datetime


database_username = 'svcpython'
database_password = 'e6$E7sQBUegYayoU'
database_ip       = '204.169.19.87'
database_name     = 'NVD'
database_connection = sqlalchemy.create_engine('mysql+mysqlconnector://{0}:{1}@{2}/{3}'.
                                               format(database_username, database_password,
                                                      database_ip, database_name))
# Pulling Data from file and creating list to iterate through
# OPEN FILE
newfile = pd.ExcelFile('/Users/beik/Desktop/Downers Grove Technical Report.xlsx')
crits = pd.read_excel(newfile, 'Critical')
# Create dataframe for CVE's from the saved file
df = pd.DataFrame(crits['CVE'])
# Drop duplicates through pandas
p_drop_dup = df.CVE.unique()
# Coonverting dataframe to list
newlist = p_drop_dup.tolist()
# Removing duplicates from ndarray
final_rm = set(newlist)
# Convert to list
last_list = list(final_rm)
# Remove NAN
last_list.remove(last_list[0])
# Sorting list
last_list.sort()
# Removeing duplicates, again
# final = list(last_list for last_list,_ in itertools.groupby(last_list))
# Joining strings together
x = ''.join([str(item) for sublist in last_list for item in sublist])
# Splitting strings
y = re.sub(r"(?P<number>\d)(?P<word>C)", r"\g<number>, \g<word>", x)
# Splitting based on CVE
z = re.sub(r'(?P<CVE>CVE-\d*-\d*)', r'\g<CVE>', y)
# Reading data
n = next(csv.reader(io.StringIO(z)))
# Creating Array
parsed_data = []
# Removing extra space and appending to array
for i in n:
    f = i.replace(' ', '')
    parsed_data.append(f)
# Getting unique values and sending to list
l2 = set(parsed_data)
l2l = list(l2)
# Sorting values
sorted = sorted(l2l)
# Creating dataframe with proper header
header = ['CVE ID']
cve_df = pd.DataFrame(sorted, columns=header)
# Converting to list, this is needed in order to pass to params in the sql query
cve_list = cve_df.values.tolist()
# Iterating over the queries and adding them to an array, this is only the case as the original query which
# only queried the db for the values in cve_list doesnt work
pub_date = []
for i in cve_list:
    r = i
    query = ("""SELECT publishedDate FROM NVD_PUB WHERE CVE_ID = %s""")
    q = pd.read_sql_query(query, con=database_connection, params=r)
    pub_date.append(q)

# Cleaning up the array
final_p_date = []
regex = re.compile(r"(\d*-\d*-\d*)")
for i in pub_date:
    match = regex.findall(str(i))
    final_p_date.append(match)
# Remove empty arrays
final_format = list(filter(None, final_p_date))

current_date = datetime.datetime.strptime('2019-06-19', '%Y-%m-%d')

thirty_days = 30
sixty_days = 60
ninety_days = 90
onetwenty = 120
six_months = 182
one_year = 365
two_year = 730
three_year = 1095

thirty_counter = 0
sixty_counter = 0
ninety_counter = 0
onetwenty_counter = 0
six_months_counter = 0
one_year_counter = 0
two_year_counter = 0
three_year_counter = 0

delta_array = []

for i in final_format:
    pday = str(i)
    pday = datetime.datetime.strptime(pday, "['%Y-%m-%d']")
    delta = abs((current_date - pday).days)
    delta_array.append(delta)
    # print(delta)

# Sorting array
delta_array.sort()


# sorted array

for i in delta_array:
    if i > three_year:
        three_year_counter += 1
    elif i > one_year <= two_year:
        two_year_counter += 1
    elif i > six_months <= one_year:
        one_year_counter += 1
    elif i > onetwenty <= six_months:
        six_months_counter += 1
    elif i > ninety_days <= onetwenty:
        onetwenty_counter += 1
    elif i > sixty_days <= ninety_days:
        ninety_counter += 1
    elif i > thirty_days <= sixty_days:
        sixty_counter += 1
    elif i <= thirty_days:
        thirty_counter += 1  # print(delta)

"""
    if i <= thirty_days:
        thirty_counter += 1# print(delta)
    elif i > thirty_days <= sixty_days:
        sixty_counter += 1
    elif i > sixty_days <= ninety_days:
        ninety_counter += 1
    elif i > ninety_days <= onetwenty:
        onetwenty_counter += 1
    elif i > onetwenty <= six_months:
        six_months_counter += 1
    elif i > six_months <= one_year:
        one_year_counter += 1
    elif i > one_year <= two_year:
        two_year_counter += 1
    elif i > three_year:
        three_year_counter += 1
"""