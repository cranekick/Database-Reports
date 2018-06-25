#!/usr/local/bin/python3

import mysql.connector
import pandas as pd

district_name = input("What is the name of the district? ")

cnx = mysql.connector.connect(user='svcpython', password='e6$E7sQBUegYayoU',
                              host='204.169.19.82',
                              database='alienvault')

cursor = cnx.cursor()

query = ("""SELECT vjobs.name as Location, hostname as Hostname, hostip as 'Host IP', service as Service, 
            scriptid as 'Vuln ID', vnp.cve_id as CVEs, vnres.risk as 'Risk Level', vnp.name, vnf.name, vnc.name,
            vnp.copyright, vnp.version, msg 
            FROM alienvault.vuln_nessus_results vnres 
            join vuln_jobs vjobs on vjobs.report_id = vnres.report_id
            join vuln_nessus_plugins vnp on vnres.scriptid = vnp.id
            join vuln_nessus_category vnc on vnc.id = vnp.category
            join vuln_nessus_family vnf on vnf.id = vnp.family
            order by vnres.risk ASC;""")

cursor.execute(query)
results = cursor.fetchall()

query1 = ("""SELECT vjobs.name as Location, vSerious as Critical, vHigh as High, vMed as Medium, vLow as Low
            from vuln_nessus_report_stats vnrstats
            join vuln_jobs vjobs on vjobs.id = vnrstats.name""")

cursor.execute(query1)
results1 = cursor.fetchall()

cursor.close()
cnx.close()

def df_shenanigans():
    header_row  = ['Location', 'Hostname', 'Host IP', 'Service', 'Vuln ID', 'CVE', 'Risk Level', 'Vulnerability', \
                    '9', '10', '11', '12', 'Blob']
    df = pd.DataFrame(results, columns=header_row)
    df = df.astype(str)
    df['Vulnerability'] = df['Vulnerability'] + '\n' + 'Family name: ' + df['9'] + '\n' + 'Category: ' + df['10'] + '\n' + \
                             'Copyright: ' + df['11'] + '\n' + 'Version: ' + df['12']
    df['Risk Level'].replace(to_replace=['1', '2', '3', '4', '5', '6', '7', '8'],
                         value=['Critical', 'High', 'Medium', 'Medium/Low', 'Low/Medium', 'Low', 'Info', \
                                'Exceptions'], inplace=True)
    df.drop(['9', '10', '11', '12'], inplace=True, axis=1)
    df['CVSS'] = df['Blob'].str.extract('Score:\s(\d.+)', expand=True)
    df['Observation'] = df['Blob'].str.extract('Summary:\n\n((?:[^\n][\n]?)+)', expand=False) # WORKS
    df['Remediation'] = df['Blob'].str.extract('Solution:\n\n((?:[^\n][\n]?)+)', expand=False) # WORKS
    df['insight'] = df['Blob'].str.extract('Insight:\n\n((?:[^\n][\n]?)+)', expand=False) # WORKS
    df['references'] = df['Blob'].str.extract('(References:\n\n(?:[^\n][\n]?)+)', expand=False) # WORKS
    df['Consequences'] = df['insight'] + '\n' + df['references']
    df['Test Output'] = df['Blob'].str.extract('Result:\n\n((?:[^\n][\n]?)+)', expand=False) # WORKS
    df['Operating System/Software'] = df['Blob'].str.extract('OS:\n\n((?:[^\n][\n]?)+)', expand=False)
    df.drop(['Blob', 'insight', 'references'], inplace=True, axis=1)

    df = df[['Location', 'Hostname', 'Host IP', 'Service', 'Risk Level', 'CVSS', 'Vuln ID', 'CVE', 'Vulnerability', \
            'Observation', 'Remediation', 'Consequences', 'Test Output', 'Operating System/Software']]
    df[['CVSS']] = df[['CVSS']].apply(pd.to_numeric)
    df.sort_values(by='CVSS', ascending=False, inplace=True)

    df.to_excel('/Users/beik/Desktop/' + district_name + '.xlsx')

df_shenanigans()



