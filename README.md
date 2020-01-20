# Firewall-Coding-Challenge

About testing: I wrote JUnit to test. If I have more time, I would add more testing cases to test direction, protocol, ip range so on. Also, changing different rules is necessary.

The rules were divided into four parts according to direction and protocol. Under each part, given a port number we have a list of intervals indicating the valid IP address. The IP is converted to Long which can be used for comparison. The interval includes the start and the end of ip address interval.

The crucial part of this task is how to quickly find the appropriate interval to compare with target. You can of course compare the target with rules one by one, which is so time consuming. 

My approach can efficiently deal with issue which uses binary search. Before binary search, we first sort and merge the intervals given by rules. The resulting intervals are sorted according to the start of interval.

The second step would be using binary search to find the index of the interval you want to compare with. For example, the target ip is 192.168.1.13, the intervals are [192.168.0.1-192.168.0.10], [192.168.1.5-192.168.1.7], [192.168.1.12-192.168.1.15], in this case we want to compare with the third interval. The binary search operation would save us time from O(n) to O(log(n)).

If I had more time, I would delve into other ways to design the data structures of rules. Also, finding the most frequent policy might be useful.

# Team Preference

1. Data Team
2. Platform Team
3. Policy Team
