import sys

def main():
	input = sys.argv[1]
	print('{"input": %s, "result":{ "requestId": "something-generated-by-whois", "someother_field": "more data"}, "summary": "something here that is so long it will need to be shortened"}' % (input))

if __name__ == "__main__":
	main()