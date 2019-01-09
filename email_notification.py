#!/usr/local/bin/python3

import smtplib
from email.message import EmailMessage

with open('/var/log/syslog') as f:
  while True:
    line = f.readline()
    if '[assessment_1-windows]' in line:
      #print(line)
      msg = EmailMessage()

      msg['Subject'] = 'Windows VPN Connection'
      msg['From'] = 'W10-SecMbl-01@sourcewelltech.org'
      msg['To'] = 'secops@ties.k12.mn.us'
      # msg['To'] = 'sam.beik@sourcewelltech.org'
      msg.set_content(line)

      s = smtplib.SMTP('prinvmex001.ties-k12.org')
      s.send_message(msg)
      s.quit()