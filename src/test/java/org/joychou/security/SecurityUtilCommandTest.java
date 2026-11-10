package org.joychou.security;

import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SecurityUtilCommandTest {

    @Test
    public void allowlistedCommandIsSplitIntoArgv() {
        assertArrayEquals(new String[]{"ls", "-la", "/tmp"}, SecurityUtil.allowedCommand("ls -la /tmp"));
        assertArrayEquals(new String[]{"whoami"}, SecurityUtil.allowedCommand("whoami"));
    }

    @Test
    public void unknownExecutableIsRejected() {
        assertNull(SecurityUtil.allowedCommand("cat /etc/passwd"));
        assertNull(SecurityUtil.allowedCommand("/bin/ls"));
        assertNull(SecurityUtil.allowedCommand("sh -c id"));
    }

    @Test
    public void shellMetacharactersInArgsAreRejected() {
        assertNull(SecurityUtil.allowedCommand("ls /tmp;id"));
        assertNull(SecurityUtil.allowedCommand("ls $(id)"));
        assertNull(SecurityUtil.allowedCommand("ls `id`"));
    }

    @Test
    public void argumentsOutsideTheAllowlistAreRejected() {
        assertNull(SecurityUtil.allowedCommand("ls /etc"));
        assertNull(SecurityUtil.allowedCommand("ls --help"));
        assertNull(SecurityUtil.allowedCommand("ls -la /tmp/../etc"));
        assertNull(SecurityUtil.allowedCommand("whoami -a"));
    }

    @Test
    public void allowedDirectoryReturnsOnlyAllowlistedLiterals() {
        assertEquals("/tmp", SecurityUtil.allowedDirectory("/tmp"));
        assertNull(SecurityUtil.allowedDirectory("/tmp;cat /etc/passwd"));
        assertNull(SecurityUtil.allowedDirectory("/etc"));
        assertNull(SecurityUtil.allowedDirectory("-la"));
        assertNull(SecurityUtil.allowedDirectory(null));
    }

    @Test
    public void canonicalHostUrlRejectsMalformedHosts() {
        assertNull(SecurityUtil.canonicalHostUrl(null));
        assertNull(SecurityUtil.canonicalHostUrl("evil.com;cat /etc/passwd"));
        assertNull(SecurityUtil.canonicalHostUrl("localhost:99999"));
    }

    @Test(expected = SSRFException.class)
    public void httpsOnlyUriRejectsPlainHttp() {
        SSRFChecker.requireSafeHttpsUri("http://93.184.216.34/");
    }

    @Test
    public void canonicalHostUrlNeverProducesPlainHttp() {
        String url = SecurityUtil.canonicalHostUrl("93.184.216.34:8443");
        if (url != null) {
            assertEquals("https://93.184.216.34:8443", url);
        }
    }

    @Test
    public void emptyInputIsRejected() {
        assertNull(SecurityUtil.allowedCommand(null));
        assertNull(SecurityUtil.allowedCommand("   "));
    }
}
