Commands used to create this output:

# log1.txt

```bash
% p4pktgen -dpl examples/demo1.p4_16.json >& log1.txt
% mv test-cases.json test-cases1.json
% mv test.pcap test1.pcap
```


# log2.txt

```bash
% p4pktgen -dpl -au examples/demo1.p4_16.json >& log2.txt
% mv test-cases.json test-cases2.json
% mv test.pcap test2.pcap
```


# log3.txt

```bash
% p4pktgen -dpl examples/demo1-no-uninit-reads.p4_16.json >& log3.txt
% mv test-cases.json test-cases3.json
% mv test.pcap test3.pcap
```
