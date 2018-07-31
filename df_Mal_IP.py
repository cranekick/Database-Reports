

import pandas as pd
import datetime


# GLOBALS
current_date = datetime.date.today()
recon_report = pd.ExcelFile('/Users/beik/Downloads/Security_Events__Reconnaissance_ALL_ASSETS.xlsx')
malicious_report = pd.ExcelFile('/Users/beik/Downloads/Activity_with_OTX_IP_Reputation_Data_ALL_ASSETS.xlsx')
IDS_events = recon_report.parse(3, header=15)
malicious_sources = malicious_report.parse(2, header=15)
df = pd.DataFrame(IDS_events['Source'])
df1 = pd.DataFrame(malicious_sources['Source'])
merge_df = df.append(df1)

def df_regex(df):
    df.replace(to_replace=":.+\n.+", value='', regex=True, inplace=True)
    df.replace(to_replace=":\n.+", value='', regex=True, inplace=True)
    df.replace(to_replace=":.+", value='', regex=True, inplace=True)
    df.replace(to_replace="\s", value='', regex=True, inplace=True)
    return df

def malicious_ips():
    sorting = sorted(set(merge_df['Source']))
    return sorting


def create_txt_file():
    with open('/Users/beik/Desktop/' + str(current_date) + ' malicious_ips.txt', 'w') as f:
        for item in malicious_ips():
            f.write('%s\n' % item)
        f.close()


def main():
    df_regex(merge_df)
    malicious_ips()
    create_txt_file()


if __name__ == '__main__':
    main()
