package org.joychou.security;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;

public class SecurityUtilCommandTest {

    @Test
    public void safeCommandMapsKeysToFixedArgv() {
        assertArrayEquals(new String[]{"whoami"}, SecurityUtil.safeCommand("whoami"));
        assertArrayEquals(new String[]{"uname", "-a"}, SecurityUtil.safeCommand("uname  -a"));
    }

    @Test
    public void safeCommandRejectsUnknownInput() {
        assertNull(SecurityUtil.safeCommand(null));
        assertNull(SecurityUtil.safeCommand("whoami;id"));
        assertNull(SecurityUtil.safeCommand("cat /etc/passwd"));
        assertNull(SecurityUtil.safeCommand("uname -r"));
    }

    @Test
    public void safeListCommandOnlyAllowsFixedDirectories() {
        assertArrayEquals(new String[]{"ls", "-la", "--", "/tmp"}, SecurityUtil.safeListCommand("/tmp"));
        assertNull(SecurityUtil.safeListCommand("/tmp;cat /etc/passwd"));
        assertNull(SecurityUtil.safeListCommand("/etc"));
        assertNull(SecurityUtil.safeListCommand(null));
    }

    @Test
    public void safeCurlCommandOnlyAllowsFixedHosts() {
        assertArrayEquals(new String[]{"curl", "--proto", "=http,https", "--", "http://localhost:8080/"},
                SecurityUtil.safeCurlCommand("localhost:8080"));
        assertNull(SecurityUtil.safeCurlCommand("hacked by joychou;cat /etc/passwd"));
        assertNull(SecurityUtil.safeCurlCommand("evil.com"));
        assertNull(SecurityUtil.safeCurlCommand(null));
    }
}
