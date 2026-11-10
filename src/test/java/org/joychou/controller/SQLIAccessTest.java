package org.joychou.controller;

import org.junit.After;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Offline tests for the object-level authorization guard in {@link SQLI}.
 */
public class SQLIAccessTest {

    @After
    public void clear() {
        SecurityContextHolder.clearContext();
    }

    private static void login(String name, String... roles) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(name, "n/a", AuthorityUtils.createAuthorityList(roles)));
    }

    @Test(expected = AccessDeniedException.class)
    public void anonymousIsDenied() {
        SQLI.requireOwnerOrAdmin("joychou");
    }

    @Test
    public void ownerIsAllowed() {
        login("joychou", "ROLE_USER");
        SQLI.requireOwnerOrAdmin("joychou");
    }

    @Test(expected = AccessDeniedException.class)
    public void otherUserIsDenied() {
        login("joychou", "ROLE_USER");
        SQLI.requireOwnerOrAdmin("admin");
    }

    @Test(expected = AccessDeniedException.class)
    public void nullUsernameIsDenied() {
        login("joychou", "ROLE_USER");
        SQLI.requireOwnerOrAdmin(null);
    }

    @Test
    public void adminIsAllowed() {
        login("admin", "ROLE_USER", "ROLE_ADMIN");
        SQLI.requireOwnerOrAdmin("joychou");
    }
}
