import os
import copy
import json
import time
import utils
import random
import argparse
import requests
import ipaddress
import geoip2.database
from pprint import pprint


# global vars
#############
logger = None
args = None
# file headers related information
headers = {
	'csv': {
		'minimal': ['IP', "Valid IP Address", "Is Public IP?", 'Maxmind GeoLocation (Continent)', 'Maxmind GeoLocation (Country)', 'Organization', 'Bad Reputed? (<Platform>)']
	}
}
#############


#############
output_json = {
	"ips": {
		# ip: {
		# 	IsValidIPAddress: "",
		# 	IsPublicIPAddress: "",
		# 	Continent: "",
		# 	Country: "",
		# 	Bad Reputed: ""
	# }
	}
}
#############


def slashes_to_use():
	ret = "/"
	if os.name == 'nt': ret = '\\'
	return ret


def update_slashes(mstr):
	return mstr.replace('/', slashes_to_use())


def setup_args():
	parser = argparse.ArgumentParser('IP Reputation Checker - {}'.format(os.path.basename(__file__)))
	parser.add_argument('-i', '--ip', metavar='<X.X.X.X>', type=str, help='IP to check reputation of. Eg: 8.8.8.8')
	parser.add_argument('-c', '--config', metavar='<config file>', type=str, help='Path to config file containing API keys. Eg: /path/to/config.json', default='config/.prod_config.json')
	parser.add_argument('-if', '--input_file', metavar='<input file>', type=str, help='Input file containing list of IPs. Eg: /path/to/ips.txt')
	parser.add_argument('-fmt', '--output_format', metavar='<output format>', type=str, default='csv', help='Output format of the data. Eg: csv')
	parser.add_argument('-of', '--output_file', metavar='<output file>', type=str, help='Output file name. Eg: /path/to/out-<epoch_time>', default='.output/out-{}'.format(time.time()))
	parser.add_argument('-cd', '--csv_delimiter', metavar='<CSV Delimiter>', type=str, default=';', help='CSV delimiter. Eg: space, comma, tab, semi colon etc.')
	logger.info('Arguments parsed successfully...')
	return parser.parse_args()


def initialize_g_vars():
	global logger, args
	logger = utils.setup_logger()
	args = setup_args()
	args.config = utils.config_file_to_dict(filename=args.config)
	logger.info('Parsed config file: ')
	pprint(args.config)
	args.output_file = update_slashes('{}.{}'.format(args.output_file, args.output_format))
	logger.info('Output file path + name: {}'.format(args.output_file))


def validate_ipaddress(ip):
	ret = True
	try:
		ip = ipaddress.ip_address(ip)
		logger.info('IP {} validated successfully...'.format(ip))
	except ValueError:
		logger.error('IP {} could not be validated...'.format(ip))
		ret = False
	return ret


def validate_public_ipaddress(ip):
	return not ipaddress.ip_address(ip).is_private


def get_country_info_for_input_file(path_geoip_db, path_ip_file):
	ret = {
		"ips": {
			# ip: {
			# 	IsValidIPAddress: "",
			# 	IsPublicIPAddress: "",
			# 	Continent: "", 
			# 	Country: "",
			# 	Bad Reputed: ""
			# }
		}
	}
	reader = geoip2.database.Reader(path_geoip_db)
	logger.info('Opened reader for GeoIP Database...')
	with open(path_ip_file) as pif:
		for ip in pif.readlines():
			ip = ip.replace('\n', '')
			ip = ip.replace('\r', '')
			if not ret.get('ips').get(ip):
				ret['ips'][ip] = {}
				# validate ip address
				is_valid = validate_ipaddress(ip)
				ret['ips'][ip]['IsValidIPAddress'] = is_valid
				if is_valid:
					is_public = validate_public_ipaddress(ip)
					ret['ips'][ip]['IsPublicIPAddress'] = is_public
					if is_public:
						country = 'Unknown'
						continent = 'Unknown'
						# organization = 'Unknown'
						# try: organization = reader.isp(ip).autonomous_system_organization
						# try: 
						# 	organization = reader.isp(ip)
						# 	pprint(organization)
						# except Exception as e: 
						# 	logger.error('Error {} occurred'.format(e))
						# 	organization = 'Unknown'
						try: dict_response = reader.country(ip)
						except Exception as e: 
							country = 'Unknown'
							continent = 'Unknown'
						try: country = dict_response.country.names.get('en')
						except Exception as e: country = 'Unknown'
						try: continent = dict_response.continent.names.get('en')
						except Exception as e: 
							continent = 'Unknown'
						# logger.info('IP: {}\tCountry: {}\tContinent: {}\tOrganization: {}'.format(ip, country, continent, organization))
						logger.info('IP: {}\tCountry: {}\tContinent: {}'.format(ip, country, continent))
						ret['ips'][ip]['Country'] = country
						ret['ips'][ip]['Continent'] = continent
						# ret['ips'][ip]['Organization'] = organization
		pprint(ret.get('ips'))
	return ret


def get_virus_total_results(api_key, output_json):
	c_output_json = copy.deepcopy(output_json)
	for ip, values in c_output_json.get('ips').items():
		url = 'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=<apikey>&ip=<ip>'.replace('<apikey>', api_key)
		if values.get('IsValidIPAddress') and values.get('IsPublicIPAddress') and (not (('organization' in output_json['ips'][ip]) or 'IsBadReputedOnVirusTotal' in output_json['ips'][ip])):
			url = url.replace('<ip>', ip)
			response = requests.get(url=url)
			# print(type(response.status_code))
			# print(response.status_code)
			organization = 'Unknown'
			is_bad_reputed = False
			if response.status_code == 200:
				response = response.json()
				logger.debug('Response converted to JSON...')
				pprint(response)
				if response.get('response_code') == 1 and 'IP address in dataset' in response.get('verbose_msg'):
					logger.debug('Org and Reputation check will be done...')
					if 'whois' in response and 'Organization' in response.get('whois'): 
						logger.debug('Org check will be done...')
						for item in response.get('whois').split('\n'):
							if 'Organization: ' in item: 
								organization = item.split('Organization: ')[1]
						logger.debug('Org check done...')
					# logic to mark as bad reputed
					if ('detected_urls' in response and len(response.get('detected_urls')) > 0) or ('detected_downloaded_samples' in response and len(response.get('detected_downloaded_samples')) > 0):
						logger.debug('Reputation check will be done...')
						is_bad_reputed = True
						logger.debug('Reputation check done...')
			output_json['ips'][ip]['Organization'] = organization
			output_json['ips'][ip]['IsBadReputedOnVirusTotal'] = is_bad_reputed
			logger.info('IP: {}\tOrganization: {}'.format(ip, organization))
			logger.info('IP: {}\tIs Bad Reputed: {}'.format(ip, is_bad_reputed))
			# sleep 15+ seconds to avoid ratelimiting
			sleep_time = random.randint(16, 20)
			logger.info('Sleeping for {} seconds to avoid ratelimiting...'.format(sleep_time))
			time.sleep(sleep_time)
	return output_json


def dict_to_csv(output_file, output_json, csv_delimiter):
	with open(output_file, 'w') as of:
		# insert header
		logger.info('Inserting header...')
		of.write('{}\n'.format(csv_delimiter.join(['IP','IsValidIPAddress','IsPublicIPAddress','Continent','Country','Organization','IsBadReputedOnVirusTotal'])))
		# insert results into file
		logger.info('Writing IP results into file...')
		for ip, values in output_json.get('ips').items():
			mstr = csv_delimiter.join([ip, '{}'.format(values.get('IsValidIPAddress')), '{}'.format(values.get('IsPublicIPAddress')), values.get('Continent'), values.get('Country'), values.get('Organization'), '{}'.format(values.get('IsBadReputedOnVirusTotal'))])
			of.write(mstr + '\n')
			logger.info(mstr)
	logger.info('Output can be found in file {}...'.format(output_file))


def main():
	try:
		initialize_g_vars()
		if args.ip:
			logger.error('Functionality not yet implemented...')
		else: 
			output_json = get_country_info_for_input_file(update_slashes(args.config.get('file_paths').get('geoip_lite_country_db')), args.input_file)
			if args.config.get('api_keys') and args.config.get('api_keys').get('virus_total'):
				output_json = get_virus_total_results(args.config.get('api_keys').get('virus_total'), output_json)
			pprint(output_json)
			if args.output_format == 'csv':
				dict_to_csv(args.output_file, output_json, args.csv_delimiter)
	except Exception as e:
		logger.error('Exception {} occurred in main of file {}...'.format(e, os.path.basename(__file__)))


# main flow of the program
##########################
main()
##########################