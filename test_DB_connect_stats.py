#!/usr/bin/python3

import mysql.connector
import pandas as pd
from openpyxl import load_workbook

cnx = mysql.connector.connect(user='svcpython', password='e6$E7sQBUegYayoU',
                              host='204.169.19.82',
                              database='alienvault')

cursor = cnx.cursor()

query = ("""SELECT vjobs.name as Location, vSerious as Critical, vHigh as High, vMed as Medium, vLow as Low
            from vuln_nessus_report_stats vnrstats
            join vuln_jobs vjobs on vjobs.id = vnrstats.name""")

cursor.execute(query)
results = cursor.fetchall()

print("Got the DATA!")

df = pd.DataFrame(results)

book = load_workbook('/Users/beik/Desktop/Farmington Final Report.xlsx')
writer = pd.ExcelWriter('/Users/beik/Desktop/Farmington Final Report.xlsx', engine='openpyxl')
writer.book = book
writer.sheets = dict((ws.title, ws) for ws in book.worksheets)

df.to_excel(writer, "Location Breakdown", header=['Location', 'Critical', 'High', 'Medium', 'Low'])

writer.save()

cursor.close()
cnx.close()


# STILL NEED TO HIDE THE FIRST COLUMN


