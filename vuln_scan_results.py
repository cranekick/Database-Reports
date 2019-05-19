#!/usr/local/bin/python3

import mysql.connector
import pandas as pd
from sys import exit
from subprocess import Popen
from time import sleep, time

start_time = time()
# This is a dependency, we are creating a background ssh tunnel, this is to be able to access the AlienVault DB
# The REQUIREMENT is the your public key is in the known_hosts on sec-mobile-one, use ssh-copy-id root@sec-mobile-one
ssh_magic = Popen(['ssh', '-N', '-L', '3306:127.0.0.1:3306', 'sec-mobile-one'], shell=False)

# Needs testing since it is a background process now

# This is for the name of the files that are created.
district_name = input("What is the name of the district? ")

# This is the query to get the Vulnerability Results from the Database
query = ("""SELECT vjobs.name as Location, hostname as Hostname, hostip as 'Host IP', service as Service, 
        scriptid as 'Vuln ID', vnp.cve_id as CVEs, vnres.risk as 'Risk Level', vnp.name, vnf.name, vnc.name,
        vnp.copyright, vnp.version, msg 
        FROM alienvault.vuln_nessus_results vnres 
        join vuln_jobs vjobs on vjobs.report_id = vnres.report_id
        join vuln_nessus_plugins vnp on vnres.scriptid = vnp.id
        join vuln_nessus_category vnc on vnc.id = vnp.category
        join vuln_nessus_family vnf on vnf.id = vnp.family
        order by vnres.risk ASC""")

# This is to get the total numbers per site as scans are based on physical locations
query1 = ("""SELECT vjobs.name as Location, vSerious as Critical, vHigh as High, vMed as Medium, vLow as Low
        from vuln_nessus_report_stats vnrstats
        join vuln_jobs vjobs on vjobs.id = vnrstats.name""")


# Accessing the AlienVault MySQL Database
def db_call(query):
    try:
        cnx = mysql.connector.connect(user='svcpython', password='e6$E7sQBUegYayoU',
                                      host='localhost',
                                      database='alienvault')
    except Exception as e:
        print("I am unable to connect to the MySQL Instance, " + str(e))
        exit(1)

    # noinspection PyUnboundLocalVariable
    cursor = cnx.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()
    cnx.close()
    print("Retrieving results from the Database.")
    return results


# GLOBAL
header_row = ['Location', 'Hostname', 'Host IP', 'Service', 'Vuln ID', 'CVE', 'Risk Level', 'Vulnerability',
              '9', '10', '11', '12', 'Blob']
header_row1 = ['Location', 'Critical', 'High', 'Medium', 'Low']
df = pd.DataFrame(db_call(query), columns=header_row)
df = df.astype(str)
df1 = pd.DataFrame(db_call(query1), columns=header_row1)
df2 = df[['Vulnerability','Risk Level']]


def df_rm_garbage():
    # The following function removes 'SCHEDULED - ' and any trailing digits (1 - 10+) in the Locations Column
    # of the DataFrame
    print("Removing 'SCHEDULED - ' and number from the Location")
    df['Location'] = df['Location'].replace(to_replace=r'SCHEDULED - ', value='', regex=True)
    df['Location'] = df['Location'].replace(to_replace=r'(\d+)', value='', regex=True)
    df1['Location'] = df1['Location'].replace(to_replace=r'SCHEDULED - ', value='', regex=True)
    df1['Location'] = df1['Location'].replace(to_replace=r'(\d+)', value='', regex=True)
    return df, df1

"""
def df_vuln_counts():
    re_index = df2[(df2['Risk Level'] == 'Critical') | (df2['Risk Level'] == 'High') | \
                      (df2['Risk Level'] == 'Medium')].groupby(['Vulnerability', 'Risk Level']) \
                       .size().reset_index(name='Quantity')
    re_index.sort_values(by=['Risk Level', 'Quantity'], ascending=[True, False])
    return re_index
"""

def df_shenanigans():
    print("Replacing 'Risk Level' integer with string.")
    print("Creating AlienVault Excel view for Columns.")
    df['Vulnerability'] = df['Vulnerability'] + '\n' + 'Family name: ' + df['9'] + '\n' + 'Category: ' + df['10'] + \
                          '\n' + 'Copyright: ' + df['11'] + '\n' + 'Version: ' + df['12']
    df['Risk Level'].replace(to_replace=['1', '2', '3', '4', '5', '6', '7', '8'],
                             value=['Critical', 'High', 'Medium', 'Medium/Low', 'Low/Medium', 'Low', 'Info',
                                    'Exceptions'], inplace=True)
    return df


def df_extract():
    # Extracting values from the AlienVault Database as it is a hodgepodge of information, this presents the information
    # like when you download the Excel
    print("Extracting fields and placing the data in AlienVault Excel view for Columns")
    df['CVSS'] = df['Blob'].str.extract('Score:\s(\d.+)', expand=True)
    df['Observation'] = df['Blob'].str.extract('Summary:\n\n((?:[^\n][\n]?)+)', expand=False)
    df['Remediation'] = df['Blob'].str.extract('Solution:\n\n((?:[^\n][\n]?)+)', expand=False)
    df['insight'] = df['Blob'].str.extract('Insight:\n\n((?:[^\n][\n]?)+)', expand=False)
    df['references'] = df['Blob'].str.extract('(References:\n\n(?:[^\n][\n]?)+)', expand=False)
    df['Consequences'] = df['insight'] + '\n' + df['references']
    df['Test Output'] = df['Blob'].str.extract('Result:\n\n((?:[^\n][\n]?)+)', expand=False)
    df['Operating System/Software'] = df['Blob'].str.extract('OS:\n\n((?:[^\n][\n]?)+)', expand=False)
    return df


def df_drop_columns():
    # Removing Columns that are no longer necessary
    print("Cleaning up the table structure. ")
    df.drop(['9', '10', '11', '12'], inplace=True, axis=1)
    df.drop(['Blob', 'insight', 'references'], inplace=True, axis=1)
    return df


def df_apply_sort():
    # This sort the DataFrame by CVSS Score. 10 - 0 in descending order. This is for precendence sake
    print("Sorting results by CVSS.")
    df[['CVSS']] = df[['CVSS']].apply(pd.to_numeric)
    df.sort_values(by='CVSS', ascending=False, inplace=True)
    return df


def main():
    db_call(query)
    db_call(query1)
    df_rm_garbage()
    # df_vuln_counts()
    df_shenanigans()
    df_extract()
    df_drop_columns()
    df_apply_sort()


if __name__ == "__main__":
    main()


df = df[['Location', 'Hostname', 'Host IP', 'Service', 'Risk Level', 'CVSS', 'Vuln ID', 'CVE', 'Vulnerability',
         'Observation', 'Remediation', 'Consequences', 'Test Output', 'Operating System/Software']]
vuln_counts = df2[(df2['Risk Level'] == 'Critical') | (df2['Risk Level'] == 'High') |\
                 (df2['Risk Level'] == 'Medium')].groupby(['Vulnerability', 'Risk Level'])\
                  .size().reset_index(name='Quantity')
vc_processed = vuln_counts.sort_values(by=['Risk Level', 'Quantity'], ascending=[True, False])

df.to_excel('/Users/beik/Desktop/' + district_name + '.xlsx')
df1.to_excel('/Users/beik/Desktop/' + district_name + ' Location Breakdown.xlsx')
vc_processed.to_excel('/Users/beik/Desktop/' + district_name + ' Vuln Counts.xlsx')
# Why the hell is this not working?????????????????


print("I am now ending the background process")
ssh_magic.kill()
print("The background process is now terminated!")
end_time = time()
running_time = (end_time - start_time) / 60
print("It took " + str(running_time) + " minutes to process.")
