import java.io.File;
import java.net.Inet4Address;
import java.util.*;

public class Firewall {


    // The rules are divided into 4 parts according to direction and protocol
    // The key to the rules is consisted of direction and protocol
    // Under this key, we store ip address range under each port
    // We use merge intervals, which results the list of ip intervals sorted according to start of ip address intervals
    // We use binary search to speed up matching process. It helps us to quickly find which interval the ip might be in

    Map<String, Map<Integer, List<long[]>>> rules;

    public Firewall(String path) throws Exception
    {
        rules = new HashMap<>();
        rules.put("inboundtcp", new HashMap<>());
        rules.put("inboundudp", new HashMap<>());
        rules.put("outboundtcp", new HashMap<>());
        rules.put("outboundudp", new HashMap<>());
        loadRules(path);

        // optimization, merge intervals, resulting list sorted according to start ip value
        for(Map<Integer, List<long[]>> map : rules.values())
        {
            for(List<long[]> intervals : map.values())
                mergeIntervals(intervals);
        }
    }


    public static void main(String[] args) throws Exception
    {
        Firewall firewall = new Firewall("data/test.csv");
        System.out.println(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
        System.out.println(firewall.accept_packet("inbound", "udp", 53, "192.168.2.30"));
        System.out.println(firewall.accept_packet("inbound", "tcp", 80, "192.168.2.2"));
        System.out.println(firewall.accept_packet("inbound", "tcp", 60, "192.168.1.2"));
    }


    private void loadRules(String path) throws Exception
    {
        File file = new File(path);
        Scanner scanner = new Scanner(file);
        while (scanner.hasNext()) {
            String rule = scanner.nextLine();
            String[] arr = rule.split(",");

            String type = arr[0] + arr[1];
            String port = arr[2];
            String ip = arr[3];

            long[] ipRange = new long[2];

            // This rule contains multiple ip
            if(ip.contains("-"))
            {
                String[] parts = ip.split("-");
                ipRange[0] = ipToLong(parts[0]);
                ipRange[1] = ipToLong(parts[1]);

            }

            // This rule contains single ip address
            else
            {
                ipRange[0] = ipToLong(ip);
                ipRange[1] = ipToLong(ip);
            }

            // This rule contains multiple ports
            if (port.contains("-"))
            {
                String[] portRange = port.split("-");
                int low = Integer.parseInt(portRange[0]);
                int high = Integer.parseInt(portRange[1]);

                for (int portNum = low; portNum <= high; portNum++)
                    addRule(rules, type, portNum, ipRange);
            }

            // This rule contains single port
            else
            {
                int portNum = Integer.parseInt(port);
                addRule(rules, type, portNum, ipRange);
            }
        }
    }


    public boolean accept_packet(String direction, String protocol, int port, String address)
    {
        String type = direction + protocol;
        if (!isValidAddress(address))
            return false;
        long ip = ipToLong(address);
        List<long[]> intervals = rules.get(type).get(port);
        if(intervals == null)
            return false;


        int searchIndex = getSearchIndex(intervals, ip);
        long[] range = intervals.get(searchIndex);
        if(isInRange(range, ip))
            return true;
        else
            return false;
    }

    // This method add a range to a specific port number under specific direction and protocol
    private void addRule(Map<String, Map<Integer, List<long[]>>> rules, String type, int portNum, long[] range)
    {
        if(rules.get(type).get(portNum) == null)
            rules.get(type).put(portNum, new ArrayList<>());

        rules.get(type).get(portNum).add(range);
    }

    // Validate a given ip address is valid or not
    private boolean isValidAddress(String address)
    {
        try
        {
            return Inet4Address.getByName(address).getHostAddress().equals(address);
        }

        catch (Exception e)
        {
            return false;
        }
    }

    // Convert ip address to long for comparison
    private long ipToLong (String address)
    {
        String[] arr = address.split("\\.");
        long ret = 0;
        for(int i = 0; i < 4; i++)
        {
            int power = 3 - i;
            ret += Integer.parseInt(arr[i]) * Math.pow(256, power);
        }
        return ret;
    }


    //Check whether a given ip is in range
    private boolean isInRange(long[] range, long ip)
    {
        return (ip >= range[0] && ip <= range[1]);
    }

    // This function merge the intervals, resulting list sorted according to ip start value
    private List<long[]> mergeIntervals(List<long[]> intervals)
    {
        Collections.sort(intervals, (a, b) -> (int) (a[0] - b[0]));
        if(intervals.size() == 0) return intervals;

        List<long[]> ret = new ArrayList<>();
        ret.add(intervals.get(0));
        for(long[] interval : intervals)
        {
            long end = ret.get(ret.size()-1)[1];
            if(interval[0] > end)
                ret.add(interval);
            else if (interval[1] > end)
                ret.get(ret.size()-1)[1] = interval[1];
        }
        return ret;
    }

    // Given a target ip, use binary search to find the index of interval to check
    private int getSearchIndex (List<long[]> intervals, long target)
    {
        if (target < intervals.get(0)[0])
            return 0;

        int low = 0;
        int high = intervals.size() - 1;

        while(low <= high)
        {
            int mid = (low + high)/2;

            if(intervals.get(mid)[0] == target)
                return mid;

            else if(intervals.get(mid)[0] > target)
                high = mid-1;
            else
                low = mid+1;
        }
        return low - 1;
    }
}
