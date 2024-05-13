# This script extracts Indicators of Compromise (IOCs) from text.
#
# Usage: python3 extract_iocs.py -f <file> -o <output>

import re
import argparse
import pathlib
from typing import List, Dict, Set, Tuple, Optional, Union
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Extract IOCs from text')
    parser.add_argument('-f', '--file', type=pathlib.Path, help='File to extract IOCs from', required=True)
    parser.add_argument('-o', '--output', type=pathlib.Path, help='Output file to write IOCs to', required=True)
    return parser.parse_args()

IOCDict = Dict[str, List[str]]
TLDs = Set[str]
FileExtensions = Set[str]
PrivateCIDRs = Set[str]

class ObservableExtractor:
    """Extract Indicators of Compromise (IOCs) from text."""

    def __init__(self, tlds: TLDs, file_extensions: FileExtensions, private_cidrs: PrivateCIDRs) -> None:
        self.tlds = tlds
        self.file_extensions = file_extensions
        self.private_cidrs = private_cidrs

    def ip_to_binary(self, ip: str) -> str:
        """Convert an IP address to its binary representation."""
        return ''.join(bin(int(octet))[2:].zfill(8) for octet in ip.split('.'))

    def is_ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if an IP address is within a given CIDR range."""
        cidr_ip, mask_length = cidr.split('/')
        binary_ip = self.ip_to_binary(ip)
        binary_cidr_ip = self.ip_to_binary(cidr_ip)
        network_portion_ip = binary_ip[:int(mask_length)]
        network_portion_cidr = binary_cidr_ip[:int(mask_length)]
        return network_portion_ip == network_portion_cidr

    def categorize_ips(self, ips: List[str]) -> Dict[str, List[str]]:
        """Categorize IP addresses as private or public."""
        categorized_ips = {
            'private': [],
            'public': []
        }
        for ip in ips:
            is_private = any(self.is_ip_in_cidr(ip, cidr) for cidr in self.private_cidrs)
            categorized_ips['private' if is_private else 'public'].append(ip)
        return categorized_ips

    def sort_ipv6_addresses(self, ipv6_list: List[str]) -> Dict[str, List[str]]:
        """Sort IPv6 addresses into different categories."""
        sorted_ips: Dict[str, List[str]] = {
            'GUA': [],
            'ULA': [],
            'LinkLocal': [],
            'Loopback': [],
            'Multicast': [],
            'IPv4Mapped': [],
            'IPv4Embedded': [],
            'Unknown': []
        }
        for ip in ipv6_list:
            normalized_ip = ip.lower()
            if normalized_ip == '::1':
                sorted_ips['Loopback'].append(ip)
            elif re.match(r'^(fc[0-9a-f]{2}|fd[0-9a-f]{2}):', normalized_ip):
                sorted_ips['ULA'].append(ip)
            elif re.match(r'^fe80:', normalized_ip):
                sorted_ips['LinkLocal'].append(ip)
            elif re.match(r'^ff00::\/8', normalized_ip):
                sorted_ips['Multicast'].append(ip)
            elif re.match(r'^::ffff:0:0:0:', normalized_ip) or re.match(r'^::ffff:', normalized_ip):
                sorted_ips['IPv4Mapped'].append(ip)
            elif re.match(r'^2002::\/16', normalized_ip) or re.match(r'^64:ff9b::\/96', normalized_ip):
                sorted_ips['IPv4Embedded'].append(ip)
            elif re.match(r'^2[0-9a-f]{3}:', normalized_ip):
                sorted_ips['GUA'].append(ip)
            else:
                sorted_ips['Unknown'].append(ip)
        return sorted_ips

    def is_valid_tld(self, domain: str) -> bool:
        """Check if a domain has a valid top-level domain."""
        domain_tld = f'.{domain.split(".")[-1]}'
        return domain_tld.lower() in self.tlds

    @staticmethod
    def extract_filenames(text: str, filename_regex: re.Pattern) -> List[str]:
        """Extract filenames from text using a regular expression."""
        return [match.group(1) for match in filename_regex.finditer(text)]

    @staticmethod
    def is_empty(value: Union[List, Dict]) -> bool:
        """Check if a list or dictionary is empty."""
        if isinstance(value, list):
            return len(value) == 0
        elif isinstance(value, dict):
            return all(ObservableExtractor.is_empty(v) for v in value.values())
        return False

    def filter_recursive(self, current_field: Union[List, Dict]) -> Union[List, Dict]:
        """Recursively filter out empty lists and dictionaries."""
        if isinstance(current_field, list):
            return current_field
        elif isinstance(current_field, dict):
            filtered = {k: self.filter_recursive(v) for k, v in current_field.items() if not self.is_empty(v)}
            return filtered
        return current_field

    @staticmethod
    def clean_user_agents(user_agents: List[str]) -> List[str]:
        """Clean user agent strings by removing trailing characters."""
        if not user_agents:
            return []
        strip_regex = re.compile(r"['`}\]]+$")
        return [strip_regex.sub('', ua) for ua in user_agents]

    def extract_iocs(self, text: str) -> IOCDict:
        """Extract IOCs from text."""
        ip_regex = re.compile(r'\b(?:\d{1,3}(?:\.\d{1,3}){3})\b')
        ipv6_regex = re.compile(r'\b(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,7}|(?:[0-9A-Fa-f]{1,4}:){1,7}:)|(?:::)(?:(?:[0-9A-Fa-f]{1,4}:){0,5}(?:[0-9A-Fa-f]{1,4}|:)){0,1}(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b')
        mac_addr_regex = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b')
        domain_regex = re.compile(r'(?:www\.)?[a-zA-Z0-9-]+(?:\[?\.\]?[a-zA-Z0-9-]+)*(?:\[?\.\]?[a-z]{2,})')
        url_regex = re.compile(r'\b(?:(?:hxxps?|hxxps?(?:\[:]\[\/]{1,2}|:\/|))|(?:fxp|fxps)(?:\[:]\[\/]{1,2}|:\/)|(?:https?|https?(?:\[:]\[\/]{1,2}|:\/))(?:\[:]\[\/]|:\/)|www(?:\[\.\]|\.))[^\s\\"]+\b')
        email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        username_regex = re.compile(r'(?:(?:user|username|user_name|_user)\s*[:=]\s*(["\']?)([^:=\s]+)\1|([^@\s/\\:]+)(?=@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b))')
        ua_regex = re.compile(r'Mozilla\/5\.0 \(.*?\) .*?\/[^\s]+(?:.*?\/[^\s]+)*')
        md5_regex = re.compile(r'\b[a-fA-F0-9]{32}\b')
        sha1_regex = re.compile(r'\b[a-fA-F0-9]{40}\b')
        sha256_regex = re.compile(r'\b[a-fA-F0-9]{64}\b')
        cve_regex = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
        reg_keys_regex = re.compile(r'\b(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)((?:\\[^\\,\.\s]+)+)\b')
        bitcoin_wallet_regex = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        etherium_wallet_regex = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
        monero_wallet_regex = re.compile(r'\b4[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{94,105}\b')

        file_extensions_pattern = '|'.join(self.file_extensions)
        filename_regex = re.compile(f'(?:\\/|\\\\|\\b)([\\w-]+\\.({file_extensions_pattern}))\\b')

        fields = {
            'ipv4Addresses': self.categorize_ips(list(set(ip_regex.findall(text)))),
            'ipv6Addresses': self.sort_ipv6_addresses(list(set(ipv6_regex.findall(text)))),
            'domains': [domain for domain in set(domain_regex.findall(text))
                        if not any(domain.replace('[', '').replace(']', '').split('.')[-1].lower() == ext
                                   for ext in self.file_extensions) and self.is_valid_tld(domain)],
            'urls': list(set(url_regex.findall(text))),
            'emails': list(set(email_regex.findall(text))),
            'usernames': list(set(username.strip('"\'') for username_tuple in username_regex.findall(text) for username in username_tuple if username)),
            'md5Hashes': list(set(md5_regex.findall(text))),
            'sha1Hashes': list(set(sha1_regex.findall(text))),
            'sha256Hashes': list(set(sha256_regex.findall(text))),
            'cveIds': list(set(cve_regex.findall(text))),
            'macAddresses': list(set(mac_addr_regex.findall(text))),
            'registryKeys': list(set([root + path for root, path in reg_keys_regex.findall(text)])),
            'filenames': list(set(self.extract_filenames(text, filename_regex))),
            'userAgents': list(set(self.clean_user_agents(ua_regex.findall(text)))),
            'bitcoinWallets': list(set(bitcoin_wallet_regex.findall(text))),
            'etheriumWallets': list(set(etherium_wallet_regex.findall(text))),
            'moneroWallets': list(set(monero_wallet_regex.findall(text)))
        }

        return self.filter_recursive(fields)

def main() -> None:
    args = get_args()
    with args.file.open('r') as file:
        text = file.read()

    # Define TLDs, file extensions, and private CIDRs
    tlds = ['.aaa','.aarp','.abb','.abbott','.abbvie','.abc','.able','.abogado','.abudhabi','.ac','.academy','.accenture','.accountant','.accountants','.aco','.actor','.ad','.ads','.adult','.ae','.aeg','.aero','.aetna','.af','.afl','.africa','.ag','.agakhan','.agency','.ai','.aig','.airbus','.airforce','.airtel','.akdn','.al','.alibaba','.alipay','.allfinanz','.allstate','.ally','.alsace','.alstom','.am','.amazon','.americanexpress','.americanfamily','.amex','.amfam','.amica','.amsterdam','.analytics','.android','.anquan','.anz','.ao','.aol','.apartments','.app','.apple','.aq','.aquarelle','.ar','.arab','.aramco','.archi','.army','.arpa','.art','.arte','.as','.asda','.asia','.associates','.at','.athleta','.attorney','.au','.auction','.audi','.audible','.audio','.auspost','.author','.auto','.autos','.aw','.aws','.ax','.axa','.az','.azure','.ba','.baby','.baidu','.banamex','.band','.bank','.bar','.barcelona','.barclaycard','.barclays','.barefoot','.bargains','.baseball','.basketball','.bauhaus','.bayern','.bb','.bbc','.bbt','.bbva','.bcg','.bcn','.bd','.be','.beats','.beauty','.beer','.bentley','.berlin','.best','.bestbuy','.bet','.bf','.bg','.bh','.bharti','.bi','.bible','.bid','.bike','.bing','.bingo','.bio','.biz','.bj','.black','.blackfriday','.blockbuster','.blog','.bloomberg','.blue','.bm','.bms','.bmw','.bn','.bnpparibas','.bo','.boats','.boehringer','.bofa','.bom','.bond','.boo','.book','.booking','.bosch','.bostik','.boston','.bot','.boutique','.box','.br','.bradesco','.bridgestone','.broadway','.broker','.brother','.brussels','.bs','.bt','.build','.builders','.business','.buy','.buzz','.bv','.bw','.by','.bz','.bzh','.ca','.cab','.cafe','.cal','.call','.calvinklein','.cam','.camera','.camp','.canon','.capetown','.capital','.capitalone','.car','.caravan','.cards','.care','.career','.careers','.cars','.casa','.case','.cash','.casino','.cat','.catering','.catholic','.cba','.cbn','.cbre','.cc','.cd','.center','.ceo','.cern','.cf','.cfa','.cfd','.cg','.ch','.chanel','.channel','.charity','.chase','.chat','.cheap','.chintai','.christmas','.chrome','.church','.ci','.cipriani','.circle','.cisco','.citadel','.citi','.citic','.city','.ck','.cl','.claims','.cleaning','.click','.clinic','.clinique','.clothing','.cloud','.club','.clubmed','.cm','.cn','.co','.coach','.codes','.coffee','.college','.cologne','.com','.commbank','.community','.company','.compare','.computer','.comsec','.condos','.construction','.consulting','.contact','.contractors','.cooking','.cool','.coop','.corsica','.country','.coupon','.coupons','.courses','.cpa','.cr','.credit','.creditcard','.creditunion','.cricket','.crown','.crs','.cruise','.cruises','.cu','.cuisinella','.cv','.cw','.cx','.cy','.cymru','.cyou','.cz','.dabur','.dad','.dance','.data','.date','.dating','.datsun','.day','.dclk','.dds','.de','.deal','.dealer','.deals','.degree','.delivery','.dell','.deloitte','.delta','.democrat','.dental','.dentist','.desi','.design','.dev','.dhl','.diamonds','.diet','.digital','.direct','.directory','.discount','.discover','.dish','.diy','.dj','.dk','.dm','.dnp','.do','.docs','.doctor','.dog','.domains','.dot','.download','.drive','.dtv','.dubai','.dunlop','.dupont','.durban','.dvag','.dvr','.dz','.earth','.eat','.ec','.eco','.edeka','.edu','.education','.ee','.eg','.email','.emerck','.energy','.engineer','.engineering','.enterprises','.epson','.equipment','.er','.ericsson','.erni','.es','.esq','.estate','.et','.eu','.eurovision','.eus','.events','.exchange','.expert','.exposed','.express','.extraspace','.fage','.fail','.fairwinds','.faith','.family','.fan','.fans','.farm','.farmers','.fashion','.fast','.fedex','.feedback','.ferrari','.ferrero','.fi','.fidelity','.fido','.film','.final','.finance','.financial','.fire','.firestone','.firmdale','.fish','.fishing','.fit','.fitness','.fj','.fk','.flickr','.flights','.flir','.florist','.flowers','.fly','.fm','.fo','.foo','.food','.football','.ford','.forex','.forsale','.forum','.foundation','.fox','.fr','.free','.fresenius','.frl','.frogans','.frontier','.ftr','.fujitsu','.fun','.fund','.furniture','.futbol','.fyi','.ga','.gal','.gallery','.gallo','.gallup','.game','.games','.gap','.garden','.gay','.gb','.gbiz','.gd','.gdn','.ge','.gea','.gent','.genting','.george','.gf','.gg','.ggee','.gh','.gi','.gift','.gifts','.gives','.giving','.gl','.glass','.gle','.global','.globo','.gm','.gmail','.gmbh','.gmo','.gmx','.gn','.godaddy','.gold','.goldpoint','.golf','.goo','.goodyear','.goog','.google','.gop','.got','.gov','.gp','.gq','.gr','.grainger','.graphics','.gratis','.green','.gripe','.grocery','.group','.gs','.gt','.gu','.gucci','.guge','.guide','.guitars','.guru','.gw','.gy','.hair','.hamburg','.hangout','.haus','.hbo','.hdfc','.hdfcbank','.health','.healthcare','.help','.helsinki','.here','.hermes','.hiphop','.hisamitsu','.hitachi','.hiv','.hk','.hkt','.hm','.hn','.hockey','.holdings','.holiday','.homedepot','.homegoods','.homes','.homesense','.honda','.horse','.hospital','.host','.hosting','.hot','.hotels','.hotmail','.house','.how','.hr','.hsbc','.ht','.hu','.hughes','.hyatt','.hyundai','.ibm','.icbc','.ice','.icu','.id','.ie','.ieee','.ifm','.ikano','.il','.im','.imamat','.imdb','.immo','.immobilien','.in','.inc','.industries','.infiniti','.info','.ing','.ink','.institute','.insurance','.insure','.int','.international','.intuit','.investments','.io','.ipiranga','.iq','.ir','.irish','.is','.ismaili','.ist','.istanbul','.it','.itau','.itv','.jaguar','.java','.jcb','.je','.jeep','.jetzt','.jewelry','.jio','.jll','.jm','.jmp','.jnj','.jo','.jobs','.joburg','.jot','.joy','.jp','.jpmorgan','.jprs','.juegos','.juniper','.kaufen','.kddi','.ke','.kerryhotels','.kerrylogistics','.kerryproperties','.kfh','.kg','.kh','.ki','.kia','.kids','.kim','.kindle','.kitchen','.kiwi','.km','.kn','.koeln','.komatsu','.kosher','.kp','.kpmg','.kpn','.kr','.krd','.kred','.kuokgroup','.kw','.ky','.kyoto','.kz','.la','.lacaixa','.lamborghini','.lamer','.lancaster','.land','.landrover','.lanxess','.lasalle','.lat','.latino','.latrobe','.law','.lawyer','.lb','.lc','.lds','.lease','.leclerc','.lefrak','.legal','.lego','.lexus','.lgbt','.li','.lidl','.life','.lifeinsurance','.lifestyle','.lighting','.like','.lilly','.limited','.limo','.lincoln','.link','.lipsy','.live','.living','.lk','.llc','.llp','.loan','.loans','.locker','.locus','.lol','.london','.lotte','.lotto','.love','.lpl','.lplfinancial','.lr','.ls','.lt','.ltd','.ltda','.lu','.lundbeck','.luxe','.luxury','.lv','.ly','.ma','.madrid','.maif','.maison','.makeup','.man','.management','.mango','.map','.market','.marketing','.markets','.marriott','.marshalls','.mattel','.mba','.mc','.mckinsey','.md','.me','.med','.media','.meet','.melbourne','.meme','.memorial','.men','.menu','.merckmsd','.mg','.mh','.miami','.microsoft','.mil','.mini','.mint','.mit','.mitsubishi','.mk','.ml','.mlb','.mls','.mm','.mma','.mn','.mo','.mobi','.mobile','.moda','.moe','.moi','.mom','.monash','.money','.monster','.mormon','.mortgage','.moscow','.moto','.motorcycles','.mov','.movie','.mp','.mq','.mr','.ms','.msd','.mt','.mtn','.mtr','.mu','.museum','.music','.mv','.mw','.mx','.my','.mz','.na','.nab','.nagoya','.name','.natura','.navy','.nba','.nc','.ne','.nec','.net','.netbank','.netflix','.network','.neustar','.new','.news','.next','.nextdirect','.nexus','.nf','.nfl','.ng','.ngo','.nhk','.ni','.nico','.nike','.nikon','.ninja','.nissan','.nissay','.nl','.no','.nokia','.norton','.now','.nowruz','.nowtv','.np','.nr','.nra','.nrw','.ntt','.nu','.nyc','.nz','.obi','.observer','.office','.okinawa','.olayan','.olayangroup','.ollo','.om','.omega','.one','.ong','.onl','.online','.ooo','.open','.oracle','.orange','.org','.organic','.origins','.osaka','.otsuka','.ott','.ovh','.pa','.page','.panasonic','.paris','.pars','.partners','.parts','.party','.pay','.pccw','.pe','.pet','.pf','.pfizer','.pg','.ph','.pharmacy','.phd','.philips','.phone','.photo','.photography','.photos','.physio','.pics','.pictet','.pictures','.pid','.pin','.ping','.pink','.pioneer','.pizza','.pk','.pl','.place','.play','.playstation','.plumbing','.plus','.pm','.pn','.pnc','.pohl','.poker','.politie','.porn','.post','.pr','.pramerica','.praxi','.press','.prime','.pro','.prod','.productions','.prof','.progressive','.promo','.properties','.property','.protection','.pru','.prudential','.ps','.pt','.pub','.pw','.pwc','.py','.qa','.qpon','.quebec','.quest','.racing','.radio','.re','.read','.realestate','.realtor','.realty','.recipes','.red','.redstone','.redumbrella','.rehab','.reise','.reisen','.reit','.reliance','.ren','.rent','.rentals','.repair','.report','.republican','.rest','.restaurant','.review','.reviews','.rexroth','.rich','.richardli','.ricoh','.ril','.rio','.rip','.ro','.rocks','.rodeo','.rogers','.room','.rs','.rsvp','.ru','.rugby','.ruhr','.run','.rw','.rwe','.ryukyu','.sa','.saarland','.safe','.safety','.sakura','.sale','.salon','.samsclub','.samsung','.sandvik','.sandvikcoromant','.sanofi','.sap','.sarl','.sas','.save','.saxo','.sb','.sbi','.sbs','.sc','.scb','.schaeffler','.schmidt','.scholarships','.school','.schule','.schwarz','.science','.scot','.sd','.se','.search','.seat','.secure','.security','.seek','.select','.sener','.services','.seven','.sew','.sex','.sexy','.sfr','.sg','.sh','.shangrila','.sharp','.shaw','.shell','.shia','.shiksha','.shoes','.shop','.shopping','.shouji','.show','.si','.silk','.sina','.singles','.site','.sj','.sk','.ski','.skin','.sky','.skype','.sl','.sling','.sm','.smart','.smile','.sn','.sncf','.so','.soccer','.social','.softbank','.software','.sohu','.solar','.solutions','.song','.sony','.soy','.spa','.space','.sport','.spot','.sr','.srl','.ss','.st','.stada','.staples','.star','.statebank','.statefarm','.stc','.stcgroup','.stockholm','.storage','.store','.stream','.studio','.study','.style','.su','.sucks','.supplies','.supply','.support','.surf','.surgery','.suzuki','.sv','.swatch','.swiss','.sx','.sy','.sydney','.systems','.sz','.tab','.taipei','.talk','.taobao','.target','.tatamotors','.tatar','.tattoo','.tax','.taxi','.tc','.tci','.td','.tdk','.team','.tech','.technology','.tel','.temasek','.tennis','.teva','.tf','.tg','.th','.thd','.theater','.theatre','.tiaa','.tickets','.tienda','.tips','.tires','.tirol','.tj','.tjmaxx','.tjx','.tk','.tkmaxx','.tl','.tm','.tmall','.tn','.to','.today','.tokyo','.tools','.top','.toray','.toshiba','.total','.tours','.town','.toyota','.toys','.tr','.trade','.trading','.training','.travel','.travelers','.travelersinsurance','.trust','.trv','.tt','.tube','.tui','.tunes','.tushu','.tv','.tvs','.tw','.tz','.ua','.ubank','.ubs','.ug','.uk','.unicom','.university','.uno','.uol','.ups','.us','.uy','.uz','.va','.vacations','.vana','.vanguard','.vc','.ve','.vegas','.ventures','.verisign','.versicherung','.vet','.vg','.vi','.viajes','.video','.vig','.viking','.villas','.vin','.vip','.virgin','.visa','.vision','.viva','.vivo','.vlaanderen','.vn','.vodka','.volvo','.vote','.voting','.voto','.voyage','.vu','.wales','.walmart','.walter','.wang','.wanggou','.watch','.watches','.weather','.weatherchannel','.webcam','.weber','.website','.wed','.wedding','.weibo','.weir','.wf','.whoswho','.wien','.wiki','.williamhill','.win','.windows','.wine','.winners','.wme','.wolterskluwer','.woodside','.work','.works','.world','.wow','.ws','.wtc','.wtf','.xbox','.xerox','.xihuan','.xin','.xn--11b4c3d','.xn--1ck2e1b','.xn--1qqw23a','.xn--2scrj9c','.xn--30rr7y','.xn--3bst00m','.xn--3ds443g','.xn--3e0b707e','.xn--3hcrj9c','.xn--3pxu8k','.xn--42c2d9a','.xn--45br5cyl','.xn--45brj9c','.xn--45q11c','.xn--4dbrk0ce','.xn--4gbrim','.xn--54b7fta0cc','.xn--55qw42g','.xn--55qx5d','.xn--5su34j936bgsg','.xn--5tzm5g','.xn--6frz82g','.xn--6qq986b3xl','.xn--80adxhks','.xn--80ao21a','.xn--80aqecdr1a','.xn--80asehdb','.xn--80aswg','.xn--8y0a063a','.xn--90a3ac','.xn--90ae','.xn--90ais','.xn--9dbq2a','.xn--9et52u','.xn--9krt00a','.xn--b4w605ferd','.xn--bck1b9a5dre4c','.xn--c1avg','.xn--c2br7g','.xn--cck2b3b','.xn--cckwcxetd','.xn--cg4bki','.xn--clchc0ea0b2g2a9gcd','.xn--czr694b','.xn--czrs0t','.xn--czru2d','.xn--d1acj3b','.xn--d1alf','.xn--e1a4c','.xn--eckvdtc9d','.xn--efvy88h','.xn--fct429k','.xn--fhbei','.xn--fiq228c5hs','.xn--fiq64b','.xn--fiqs8s','.xn--fiqz9s','.xn--fjq720a','.xn--flw351e','.xn--fpcrj9c3d','.xn--fzc2c9e2c','.xn--fzys8d69uvgm','.xn--g2xx48c','.xn--gckr3f0f','.xn--gecrj9c','.xn--gk3at1e','.xn--h2breg3eve','.xn--h2brj9c','.xn--h2brj9c8c','.xn--hxt814e','.xn--i1b6b1a6a2e','.xn--imr513n','.xn--io0a7i','.xn--j1aef','.xn--j1amh','.xn--j6w193g','.xn--jlq480n2rg','.xn--jvr189m','.xn--kcrx77d1x4a','.xn--kprw13d','.xn--kpry57d','.xn--kput3i','.xn--l1acc','.xn--lgbbat1ad8j','.xn--mgb9awbf','.xn--mgba3a3ejt','.xn--mgba3a4f16a','.xn--mgba7c0bbn0a','.xn--mgbaam7a8h','.xn--mgbab2bd','.xn--mgbah1a3hjkrd','.xn--mgbai9azgqp6j','.xn--mgbayh7gpa','.xn--mgbbh1a','.xn--mgbbh1a71e','.xn--mgbc0a9azcg','.xn--mgbca7dzdo','.xn--mgbcpq6gpa1a','.xn--mgberp4a5d4ar','.xn--mgbgu82a','.xn--mgbi4ecexp','.xn--mgbpl2fh','.xn--mgbt3dhd','.xn--mgbtx2b','.xn--mgbx4cd0ab','.xn--mix891f','.xn--mk1bu44c','.xn--mxtq1m','.xn--ngbc5azd','.xn--ngbe9e0a','.xn--ngbrx','.xn--node','.xn--nqv7f','.xn--nqv7fs00ema','.xn--nyqy26a','.xn--o3cw4h','.xn--ogbpf8fl','.xn--otu796d','.xn--p1acf','.xn--p1ai','.xn--pgbs0dh','.xn--pssy2u','.xn--q7ce6a','.xn--q9jyb4c','.xn--qcka1pmc','.xn--qxa6a','.xn--qxam','.xn--rhqv96g','.xn--rovu88b','.xn--rvc1e0am3e','.xn--s9brj9c','.xn--ses554g','.xn--t60b56a','.xn--tckwe','.xn--tiq49xqyj','.xn--unup4y','.xn--vermgensberater-ctb','.xn--vermgensberatung-pwb','.xn--vhquv','.xn--vuq861b','.xn--w4r85el8fhu5dnra','.xn--w4rs40l','.xn--wgbh1c','.xn--wgbl6a','.xn--xhq521b','.xn--xkc2al3hye2a','.xn--xkc2dl3a5ee0h','.xn--y9a3aq','.xn--yfro4i67o','.xn--ygbi2ammx','.xn--zfr164b','.xxx','.xyz','.yachts','.yahoo','.yamaxun','.yandex','.ye','.yodobashi','.yoga','.yokohama','.you','.youtube','.yt','.yun','.za','.zappos','.zara','.zero','.zip','.zm','.zone','.zuerich','.zw']
    file_extensions = ["aac", "adt", "adts", "accdb", "accde", "accdr", "accdt", "aif", "aifc", "aiff", "aspx", "avi", "bat", "bin", "bmp", "cab", "cda", "csv", "dif", "dll", "doc", "docm", "docx", "dot", "dotx", "eml", "eps", "exe", "flv", "gif", "htm", "html", "ini", "iso", "jar", "jpg", "jpeg", "m4a", "mdb", "mid", "midi", "mov", "mp3", "mp4", "mpeg", "mpg", "msi", "mui", "pdf", "png", "pot", "potm", "potx", "ppam", "pps", "ppsm", "ppsx", "ppt", "pptm", "pptx", "psd", "pst", "pub", "rar", "rtf", "scr", "sldm", "sldx", "swf", "sys", "tif", "tiff", "tmp", "txt", "vob", "vsd", "vsdm", "vsdx", "vss", "vssm", "vst", "vstm", "vstx", "wav", "wbk", "wks", "wma", "wmd", "wmv", "wmz", "wms", "wpd", "wp5", "xla", "xlam", "xll", "xlm", "xls", "xlsm", "xlsx", "xlt", "xltm", "xltx", "xps", "zip"]
    private_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]

    extractor = ObservableExtractor(tlds, file_extensions, private_cidrs)
    iocs = extractor.extract_iocs(text)

    with args.output.open('w') as output_file:
        for key, value in iocs.items():
            if value:
                output_file.write(f'{key}:\n')
                for item in value:
                    output_file.write(f'{item}\n')
                output_file.write('\n')

    logging.info('IOCs extracted and written to %s', args.output)

if __name__ == '__main__':
    main()
    
