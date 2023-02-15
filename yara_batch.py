from re import findall, MULTILINE as multiline, DOTALL
import math
import argparse

def get_args():
    parser = argparse.ArgumentParser(description='Create smaller batches of yara rules for testing.')
    parser.add_argument('-f','--file', help='Yara rule file to process', required=True)
    parser.add_argument('-o','--output', help='Output processed yara rules to this folder', required=True)
    parser.add_argument('-b','--batch', help='Batch size of yara rules to write to each file', type=int, required=False, default='300')
    return(parser.parse_args())

def main():
    args = get_args()
    data = open(args.file, 'r').read()
    output = args.output
    rules = findall('(?:^private\srule|^rule).+?condition:.+?^\}', data, multiline|DOTALL)

    num_rules = len(rules)
    batch_size = args.batch
    blocks = math.ceil(num_rules / batch_size)
    count_rules = 0
    print(f'Total rules: {num_rules}')
    print(f'Batch size: {batch_size}')
    print(f'Number of blocks: {blocks}')
    for i in range(blocks):
        rule_ready = ''
        count_rules_block = 0
        for rule in rules[i*batch_size:(i+1)*batch_size]:
            count_rules += 1
            count_rules_block += 1
            rule_ready += rule + '\n\n'
        with open(f'{output}\\batch_{i + 1}.yara', 'w') as f1:
            f1.write(rule_ready)
        print(f'{count_rules_block} rules written to {output}\\batch_{i + 1}.yara')
    print(f'Total rules written: {count_rules}')

if __name__ == '__main__':
    main()