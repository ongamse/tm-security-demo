package org.joychou.security;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
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
    public void emptyInputIsRejected() {
        assertNull(SecurityUtil.allowedCommand(null));
        assertNull(SecurityUtil.allowedCommand("   "));
    }
}
