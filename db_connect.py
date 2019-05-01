#!/usr/bin/python3
import pdb
import mysql.connector

#district_name = input("What is the name of the district? ")

cnx = mysql.connector.connect(user='root', password='fr8Ede9MWH',
                              host='204.169.19.82',
                              database='alienvault')

cursor = cnx.cursor()

query = ("""select vnrep.name as Location, vnres.hostname as Hostname, vnres.hostIP as IP, vnres.service as Service,
            vnres.scriptid as VulnID, vnpfeed.cve_id, vnres.risk, vnpfeed.name, vnffeed.name as familyname, 
            vncfeed.name as categoryname, vnpfeed.copyright, vnpfeed.version, vnres.msg, vnpfeed.description 
            as Consequences
            from vuln_nessus_reports vnrep
            join vuln_nessus_results vnres on vnres.report_id = vnrep.report_id
            join vuln_nessus_plugins_feed vnpfeed on vnpfeed.id = vnres.scriptid
            join vuln_nessus_family_feed vnffeed on vnffeed.id = vnpfeed.family
            join vuln_nessus_category_feed vncfeed on vncfeed.id = vnpfeed.category
            order by vnres.risk DESC
            INTO OUTFILE '/var/lib/mysql-files/rodeo.csv'
            FIELDS TERMINATED BY ','
            LINES TERMINATED BY '\r\n'""")

cursor.execute(query)

cursor.close()
cnx.close()
