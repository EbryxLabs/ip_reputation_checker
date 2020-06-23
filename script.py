import os
import time
import utils
import geoip
import argparse
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
	logger = setup_logger()
	args = setup_args()
	args.config = config_file_to_dict(filename=args.config)
	logger.info('Parsed config file: ')
	pprint(args.config)
	args.output_file = '{}.{}'.format(args.output_file, args.output_format)
	logger.info('Output file path + name: {}'.format(args.output_file))


def main():
	try:
		initialize_g_vars()
	except Exception as e:
		logger.error('Exception {} occurred in main of file {}...'.format(e, os.path.basename(__file__)))


# main flow of the program
##########################
main()
##########################