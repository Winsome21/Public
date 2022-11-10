#!/usr/bin/python3

from re import findall, sub, search, compile as recompile, MULTILINE as multiline, split, DOTALL as dotall
import argparse

def get_args():
    parser = argparse.ArgumentParser(description='test')
    parser.add_argument('-f','--file',help='Yara rules file to process.',required=True)
    parser.add_argument('-o','--output',help='Output yara rules to this file.',required=True)
    parser.add_argument('-l','--list',help='List of rule names that need to be removed if found.')
    parser.add_argument('-m','--mode',help='"-m dedup" is dedup mode. "-m remove" is remove mode and removes rules that match provided list.',required=True)
    return(parser.parse_args())

def regex_rules_remove(rules,rule_list):
    reg1 = recompile(r'^rule\s.+?(?=^rule)',multiline|dotall)
    all_rules = findall(reg1,rules)
    rule_dict = {}
    for item in all_rules:
        prep = item.strip()
        rule_name = findall('(?<=^rule\s)[^\s\:\n]+',prep)
        try:
            if not rule_name[0] in rule_list:
                rule_dict[rule_name[0]] = prep
            else:
                print('{} is a duplicate and was removed.'.format(rule_name[0]))
        except:
            continue
    rule_ready = ''
    for rule in rule_dict.values():
        rule_ready += (rule + '\n\n')
    return(rule_ready)

def regex_rules_dedup(rules):
    reg1 = recompile(r'^rule\s.+?(?=^rule)',multiline|dotall)
    all_rules = findall(reg1,rules)
    rule_dict = {}
    for item in all_rules:
        prep = item.strip()
        rule_name = findall('(?<=^rule\s)[^\s\:\n]+',prep)
        try:
            if not rule_name[0] in rule_dict.keys():
                rule_dict[rule_name[0]] = prep
            else:
                rule_dict[rule_name[0]] = prep
                print('{} is a duplicate and was overwritten.'.format(rule_name[0]))
        except:
            print('Failed to process #1')
    rule_ready = ''
    for rule in rule_dict.values():
        rule_ready += (rule + '\n\n')
    return(rule_ready)

if __name__ == '__main__':
    args = get_args()
    yara_rules = open(args.file,'r').read()
    print('Opening "{}"'.format(args.file))
    rules_deduped = ''
    imports = findall('^import [^\n]+',yara_rules)
    for item in list(set(imports)):
        rules_deduped += (item + '\n')
    if len(imports)>0:
        rules_deduped += '\n'
    if args.mode == 'dedup':
        print('Processing Yara Rules')
        rules_deduped += regex_rules_dedup(yara_rules)
    elif args.mode == 'remove':
        try:
            rules_list = open(args.list,'r').read().split('\n')
            rules_deduped += regex_rules_remove(yara_rules,rules_list)
        except:
            print('Please provide yara rules file with -f and a list of rule names to check against with -l')
    else:
        print('Failed to process')
    
    f1 = open(args.output,'w')
    f1.write(rules_deduped)
    f1.close()
