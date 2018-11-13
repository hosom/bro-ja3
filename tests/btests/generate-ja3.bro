# @TEST-EXEC: bro -b -r $TRACES/ssl.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log

@load ../../../scripts
