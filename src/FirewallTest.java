import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FirewallTest
{
    @Test
    public void test1() throws Exception {
        Firewall firewall = new Firewall("data/test.csv");
        assertTrue(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
    }

    @Test
    public void test2() throws Exception {
        Firewall firewall = new Firewall("data/test.csv");
        assertTrue(firewall.accept_packet("outbound", "tcp", 60000, "192.168.10.11"));
    }


    @Test
    public void test3() throws Exception {
        Firewall firewall = new Firewall("data/test.csv");
        assertTrue(firewall.accept_packet("inbound","udp",60,"192.168.2.5"));
    }


    @Test
    public void test4() throws Exception {
        Firewall firewall = new Firewall("data/test.csv");
        assertTrue(firewall.accept_packet("outbound", "udp", 2000, "52.12.48.92"));
    }

    @Test
    public void test6() throws Exception {
        Firewall firewall = new Firewall("data/test.csv");
        assertTrue(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.6"));
    }

}

