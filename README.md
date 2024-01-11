This Captures the live packets from the wifi or erhenet interface and parses only DNS packets. 
the entire DNS payload is parsed, DNS queries, responses, srcport, dstport, src ipaddress, destination ip address. 
complete DNS paylod is printed on the terminal
Basically it does deep packet inspection of the DNS payload.

steps to run the program :
    1. sudo go run dns_parser.go en0

Still need to fix the parsing of the DNS responses field in the DNS payload.

