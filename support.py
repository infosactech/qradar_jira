#!/usr/bin/python
# coding=utf-8

from pprint import pprint
from os import path
from jira import JIRA, JIRAError
import pickle
import requests
import datetime

# Script for posting events in Jira

# Fill
JIRA_LOGIN = 'user' # Jira user
JIRA_PASS = 'password' # Jira password
JIRA_URL = 'https://jira.example.com/' # Change hostname line 16, 46, 86
SIEM_KEY = 'xxxx-xxxx-xxxx' # Set Auth Token Qradar


def post_jira_issue(url, raw_payload):
    jira_options = {'server': url, 'verify': False}
    jira = JIRA(options=jira_options, basic_auth=(JIRA_LOGIN, JIRA_PASS))
    try:
        result = jira.create_issue(raw_payload)
    except JIRAError as e:
        print e.status_code, e.text
        return 0
    return result


def get_siem_offenses(base_url, sec_code,
                      fields="id,description,status,start_time,severity,offense_source,source_network,"
                             "destination_networks"):
    headers = {
        'sec': sec_code,
        'version': '8.1',
    }
    response = requests.get(base_url + 'api/siem/offenses', headers=headers,
                            params={"fields": fields, "filter": "status=OPEN"}, verify=False)
    return response.json()


def convert_offense_for_jira(raw_offense):
    time = raw_offense['start_time'] / 1000.0
    time = datetime.datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
    offense_url = 'https://siem.example.com/console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={id}'.format(
        id=raw_offense['id'])
    try:
        source = raw_offense['offense_source'].decode('utf-8')
    except:
        source = " "

    fields_dict = {
        'project': {'key': 'SIEM'},
        'summary': 'Offense id: {oid} {title}'.format(oid=raw_offense['id'], title=raw_offense['description']).replace(
            '\n', ''),
        'description': '|*Time*||{time}|\r\n|*Source*||{source}|\r\n|*Secerity*||{severity}|\r\n|*Description*||{description}|\r\n|*Source Network*||{source_network}|\r\n|*Destination Networks*||{destination_networks}|\r\n|*URL*||[Offense {id}|{offense_url}]|'.format(
            source=source,
            description=raw_offense['description'].replace('\n', ''), severity=raw_offense['severity'], time=time,
            source_network=raw_offense['source_network'], destination_networks=raw_offense['destination_networks'],
            offense_url=offense_url, id=raw_offense['id']),
        'issuetype': {'name': 'Task'}
    }
    return fields_dict


def load_cache(filename='cache.pkl'):
    if not path.exists(filename):
        return set()

    with open(filename, 'rb') as f:
        return pickle.load(f)


def save_cache(cache, filename='cache.pkl'):
    with open(filename, 'wb') as f:
        pickle.dump(cache, f)


if __name__ == '__main__':
    sent_offenses_cache = load_cache()
    print('in cache:')
    pprint(sent_offenses_cache)
    min_offense_id = 2016

    offenses = get_siem_offenses('https://siem.example.com/', SIEM_KEY) # Change settings
    offenses_not_in_cache = (offense for offense in offenses if offense['id'] not in sent_offenses_cache)

    for offense in offenses:
        offense_id = int(offense['id'])
        min_offense_id = offense_id if (min_offense_id is None) else min(offense_id, min_offense_id)

    for offense in offenses_not_in_cache:
        offense_id = int(offense['id'])
        jira_issue = convert_offense_for_jira(offense)

        print('posting offense #: %d ...' % offense_id)
        post_jira_issue(JIRA_URL, jira_issue)

        sent_offenses_cache.add(offense_id)

    if min_offense_id is not None:
        print('removing items from cache, older than # %d ...' % min_offense_id)
        sent_offenses_cache = set((x for x in sent_offenses_cache if x >= min_offense_id))

    # save cache
    save_cache(sent_offenses_cache)
