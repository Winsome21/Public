#!/usr/bin/python3

from re import findall, sub, search, compile as recompile, MULTILINE as multiline, split
from datetime import date
import argparse

default_fields = {'actor_types':'CRIMEWARE',
                'category':'malware',
                'malware_type':'TROJAN',
                'sharing':'TLP:AMBER',
                'status':'TESTING',
                'version':'1.0'}

required_fields = ['actor_types','author','category','creation_date',
                'description','first_imported','hash','last_modified',
                'malware','malware_type','reference','sharing',
                'status','version']

valid_values = {'actor_types': ['APT','CRIMEWARE','FIN'],
                    'category': ['info','exploit','technique','tool','malware'],
                    'malware_type': ["ADWARE","APT","BACKDOOR","BANKER",
                      "BOOTKIT","BOT","BROWSER-HIJACKER",
                      "BRUTEFORCER","CLICKFRAUD","CRYPTOMINER",
                      "DDOS","DOWNLOADER","DROPPER","EXPLOITKIT",
                      "FAKEAV","HACKTOOL","INFOSTEALER","KEYLOGGER",
                      "LOADER","OBFUSCATOR","POS","PROXY","RAT",
                      "RANSOMWARE","REVERSE-PROXY","ROOTKIT","SCANNER",
                      "SCAREWARE","SPAMMER","TROJAN","VIRUS","WIPER",
                      "WEBSHELL","WORM"],
                    'sharing': ['TLP:WHITE','TLP:GREEN','TLP:AMBER'],
                    'status': ['TESTING','RELEASED','DEPRECATED']}

def get_args():
    parser = argparse.ArgumentParser(description='Attempt to fix and provide feedback on yara rule metadata.')
    parser.add_argument('-f','--file',help='Yara rule file to process',required=True)
    parser.add_argument('-o','--output',help='Output processed yara rules to this file',required=True)
    parser.add_argument('-r','--reports',help='Output reports containing feedback for each processed yara rule.')
    return(parser.parse_args())

def parse_meta_fields(rule):
    #Normalize for processing
    prep_normalized_rule = sub('(\'|\“|\”)','\"',rule)
    prep_normalized_rule2 = sub('(\t+|\s+)',' ',prep_normalized_rule)
    normalized_rule = sub('(\r|\n)','',prep_normalized_rule2)
    
    #Regex to get rule name
    get_rule = findall('(?i)^\s*rule\s*(?P<rulename>[^\n\{]+)',normalized_rule)
    rulename = get_rule[0].strip()
    #Regex patterns to get metadata
    get_meta = recompile(r'meta\:(?P<metadata>.+)strings\:',multiline)
    get_meta_values = recompile(r'(?P<key>[^\s\=]+)\s*\=\s*\"(?P<value>[^\"]+)\"',multiline)
    
    #Regex to extract metadata
    meta = findall(get_meta,normalized_rule)
    values = findall(get_meta_values,str(meta))
    
    #Create dictionary of extracted metadata
    fields = dict(values)
    
    return rulename,fields

def check_expected_field_values(rule,fields):
    passed = 'Passed'
    prep_report = ""
    fields = {k.lower(): v for k, v in fields.items()}
        
    for required_field in required_fields:
        if not required_field in fields:
            fields[required_field] = ""
    
    for key,value in valid_values.items():
        if not fields[key] in value:
            prep_report += '{} = \"{}\" is not valid. Provide one of the following values: {}\n'.format(key,fields[key],value)
            passed = 'Failed'
        else:
            continue
    
    #Check author
    if len(fields['author'])>0 and not bool(findall('\@',fields['author'])):
        fields['author'] = '@' + fields['author']
    elif len(fields['author'])==0:
        prep_report += 'author = \"{}\" is not valid. Please provide an author.\n'.format(fields['author'])
        passed = 'Failed'
    
    #Check creation date
    if not bool(findall('^20\d{2}\-[0-1][0-9]\-[0-3][0-9]$',fields['creation_date'])):
        prep_report += 'creation_date = \"{}\" is not valid. please provide date in the following format: YYYY-MM-DD\n'.format(fields['creation_date'])
        passed = 'Failed'
    
    #Check description
    if not len(fields['description'])>0:
        prep_report += 'description = \"{}\" is not valid. Please provide a description.\n'.format(fields['description'])
        passed = 'Failed'

    #Check first imported
    if not bool(findall('^20\d{2}\-[0-1][0-9]\-[0-3][0-9]$',fields['first_imported'])):
        prep_report += 'first_imported = \"{}\" is not valid. please provide date in the following format: YYYY-MM-DD\n'.format(fields['first_imported'])
        passed = 'Failed'
    
    #Check hash
    if not bool(findall('(?i)^([a-f0-9]{64}|[a-f0-9]{48}|[a-f0-9]{32})$',fields['hash'])):
        prep_report += 'hash = \"{}\" is invalid. Please provide a valid hash.\n'.format(fields['hash'])
        passed = 'Failed'
    
    #Check last modified
    if not bool(findall('^20\d{2}\-[0-1][0-9]\-[0-3][0-9]$',fields['last_modified'])):
        prep_report += 'last_modified = \"{}\" is not valid. please provide date in the following format: YYYY-MM-DD\n'.format(fields['last_modified'])
        passed = 'Failed'
    
    #Check malware name
    if not len(fields['malware'])>0:
        prep_report += 'malware = \"{}\" is invalid. Please provide a malware name.\n'.format(fields['malware'])
        passed = 'Failed'
    
    #Check reference
    if not len(fields['reference'])>0:
        prep_report += 'reference = \"{}\" is invalid. Please provide a reference.\n'.format(fields['reference'])
        passed = 'Failed'

    #Check version
    if not len(fields['version'])>0:
        prep_report += 'version = \"{}\" is invalid. Please provide a version number.\n'.format(fields['version'])
        passed = 'Failed'
    
    #Create report based on findings
    report = '{}\n------------------------------------\n{} validation.'.format(rule,passed)
    if len(prep_report)>0:
        report += '\n------------------------------------\n{}------------------------------------\n'.format(prep_report)
    else:
        report += '\n------------------------------------'
    report += '\n'
    
    sorted_fields = dict(sorted(fields.items()))
    
    return report,sorted_fields

def fix_expected_fields(fields):
    fields = {k.lower(): v for k, v in fields.items()}    

    #Create empty required fields if missing.
    for required_field in required_fields:
        if not required_field in fields:
            fields[required_field] = ""

    #Check required fields, add required fields if missing, and add default values to them.
    for required_field in required_fields:
        if required_field in default_fields.keys() and not required_field in fields.keys():
            fields[required_field] = default_fields[required_field]
        elif required_field in default_fields.keys() and len(fields[required_field]) == 0:
            fields[required_field] = default_fields[required_field]
        elif required_field in default_fields.keys() and len(fields[required_field]) > 0 and not fields[required_field] in valid_values[required_field]:
            fields[required_field] = default_fields[required_field]
        else:
            continue
    
    #Check author
    if len(fields['author'])>0 and not bool(findall('\@',fields['author'])):
        fields['author'] = '@' + fields['author']
    
    #Check creation date
    if len(fields['creation_date'])==0 or not bool(findall('^20\d{2}\-[0-1][0-9]\-[0-3][0-9]$',fields['creation_date'])):
        fields['creation_date'] = date.today().strftime("%Y-%m-%d")    
    
    #Check description
    if len(fields['malware'])>0 and not len(fields['description'])>0:
        fields['description'] = 'Detects {}'.format(fields['malware'])

    #Check first imported
    if len(fields['first_imported'])==0 or not bool(findall('^20\d{2}\-[0-1][0-9]\-[0-3][0-9]$',fields['first_imported'])):
        fields['first_imported'] = date.today().strftime("%Y-%m-%d")
    
    #Check hash
    if len(fields['hash'])==0:
        for key,value in fields.items():
            if bool(findall('(?i)^([a-f0-9]{64}|[a-f0-9]{48}|[a-f0-9]{32})$',value)):
                fields['hash'] = value
                del fields[key]
                break
    
    #Check last modified
    if len(fields['last_modified'])==0 or not bool(findall('^20\d{2}\-[0-1][0-9]\-[0-3][0-9]$',fields['last_modified'])):
        fields['last_modified'] = date.today().strftime("%Y-%m-%d")
    
    #Check reference
    if len(fields['hash'])>0 and not len(fields['reference'])>0:
        fields['reference'] = 'https://www.virustotal.com/gui/file/{}'.format(fields['hash'])
    
    sorted_fields = dict(sorted(fields.items()))
    return sorted_fields

def main(rule):
    rulename,fields = parse_meta_fields(rule)
    fixed_fields = fix_expected_fields(fields)
    report,more_fields = check_expected_field_values(rulename,fixed_fields)
    find_meta = search('meta:',rule)
    find_strings = search('strings:',rule)
    make_list = ""
    for key,value in fixed_fields.items():
        if not key[0] == '$':
            make_list += '\n        {} = \"{}\"'.format(key,value)
    make_list += '\n'
    new_rule = rule.replace(rule[find_meta.end():find_strings.start()-4],make_list)
    new_rule += '\n\n'
    return(new_rule,report)

if __name__ == "__main__":
    args = get_args()
    yara_rules = split('\n\n(?=rule)',open(args.file).read())
    rule_ready = ""
    if 'import' in yara_rules[0]:
        rule_ready += yara_rules[0] + '\n\n'
    report_ready = ""
    for count,rule in enumerate(yara_rules):
        try:
            yara_rule_fixed,reports = main(rule)
            rule_ready += yara_rule_fixed
            report_ready += reports
        except:
            print('Failed to process rule {}'.format(count))
    
    f1 = open(args.output, "w")
    f1.write(rule_ready)
    f1.close()
    
    if args.reports:
        f2 = open(args.reports, "w")
        f2.write(report_ready)
        f2.close()
