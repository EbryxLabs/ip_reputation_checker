import os
import time
import utils
import argparse
import geoip2.database
from pprint import pprint


# global vars
#############
logger = None
args = None
# file headers related information
headers = {
	'csv': {
		'minimal': ['IP', 'Maxmind GeoLocation (Country)', 'Bad Reputed? (<Platform>)']
	}
}
#############


#############
output_json = {
	"ips": {
		# ip: {
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
	parser.add_argument('-of', '--output_file', metavar='<output file>', type=str, help='Output file name. Eg: /path/to/out-<epoch_time>', default='output/out-{}'.format(time.time()))
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


def get_country_info_for_input_file(path_geoip_db, path_ip_file):
	ret = {
		"ips": {
			# ip: {
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
			country = 'Unknown'
			try: country = reader.country(ip).country.names.get('en')
			except Exception as e: country = 'Unknown'
			logger.info('IP: {}\tCountry: {}'.format(ip, country))
			ret['ips'][ip] = {
				'Country': country
			}
		pprint(ret.get('ips'))
	return ret


def main():
	try:
		initialize_g_vars()
		if args.ip:
			logger.info('IP worked...')
		else: 
			output_json = get_country_info_for_input_file(update_slashes(args.config.get('file_paths').get('geoip_lite_country_db')), args.input_file)
	except Exception as e:
		logger.error('Exception {} occurred in main of file {}...'.format(e, os.path.basename(__file__)))


# main flow of the program
##########################
main()
##########################