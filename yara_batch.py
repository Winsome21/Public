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
    rules = findall('(?:^private\srule|^rule).+?^\}', data, multiline|DOTALL)

    num_rules = len(rules)
    batch_size = args.batch
    blocks = math.ceil(num_rules / batch_size)
    count_rules = 0
    print('Total rules: {}'.format(num_rules))
    print('Batch size: {}'.format(batch_size))
    print('Number of blocks: {}'.format(blocks))
    for i in range(0, blocks):
        rule_ready = ''
        count_rules_block = 0
        for rule in rules[i*batch_size:(i+1)*batch_size]:
            count_rules += 1
            count_rules_block += 1
            rule_ready += rule + '\n\n'
        f1 = open('{}\\batch_{}.yara'.format(output, i+1), 'w')
        f1.write(rule_ready)
        f1.close()
        print('{} rules written to {}\\batch_{}.yara'.format(count_rules_block, output, i+1))
    print('Total rules written: {}'.format(count_rules))

if __name__ == '__main__':
    main()