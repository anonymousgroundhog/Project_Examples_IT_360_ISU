import nvdlib, os, datetime, pandas as pd
from termcolor import colored, cprint

def get_latest_vulnerabilities(this_key):
    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=7)
    df = pd.DataFrame(columns=['id', 'score','description'])
    lst_ids = []
    lst_dates = []
    lst_scores = []
    lst_descriptions = []

    results = nvdlib.searchCVE(pubStartDate=start, pubEndDate=end, key=this_key)
    for cve in results:
        description = cve.descriptions[0]
        lst_ids.append(cve.id)
        lst_dates.append(cve.published)
        lst_scores.append(cve.score[2])
        lst_descriptions.append(description.value)
    df['id'] = lst_ids
    df['score'] = lst_scores
    df['description'] = lst_descriptions
    return(df)

os.system('clear')
key=input('Type in key and press enter:')

cprint('Key: '+key + '\n','green')

print(get_latest_vulnerabilities(key))
