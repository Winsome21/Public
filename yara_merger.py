from re import findall, MULTILINE as multiline, DOTALL
import math
import argparse
import glob

def get_args():
    parser = argparse.ArgumentParser(description='Create smaller batches of yara rules for testing.')
    parser.add_argument('-f','--folder', help='Yara rule file to process', required=True)
    parser.add_argument('-o','--output', help='Output processed yara rules to this folder', required=True)
    return(parser.parse_args())

def main():
    args = get_args()
    filepath = args.folder + '\\*'
    filenames = glob.glob(filepath)
    rule_count = 0
    imported = []
    rules_ready = ''
    imports_ready = ''
    for fname in filenames:
        with open(fname, 'r') as readfile:
            infile = readfile.read()
            imports = findall('import\s+\"(.*?)\"', infile)
            rules = findall('(?:^private\srule|^rule).+?^\}', infile, multiline|DOTALL)
            rule_count += len(rules)
            for rule in rules:
                rules_ready += rule + '\n\n'
            for imp in imports:
                if imp not in imported:
                    imported.append(imp)

    for imp in list(set(imported)):
        imports_ready += 'import "' + imp + '"\n'
    final_ready = imports_ready + '\n' + rules_ready
    print('{} rules written to {}.'.format(rule_count, args.output))
    outfile = open(args.output, 'w')
    outfile.write(final_ready)
    outfile.close()

if __name__ == '__main__':
    main()