package org.joychou.controller;

import org.joychou.dao.User;
import org.joychou.mapper.UserMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SQLIAuthorizationTest {

    private SQLI controller;

    @Before
    public void setUp() throws Exception {
        controller = new SQLI();
        UserMapper mapper = (UserMapper) Proxy.newProxyInstance(
                UserMapper.class.getClassLoader(),
                new Class<?>[]{UserMapper.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) {
                        if ("findByUserName".equals(method.getName()) && "bob".equals(args[0])) {
                            User u = new User();
                            u.setId(2);
                            u.setUsername("bob");
                            return u;
                        }
                        return null;
                    }
                });
        Field f = SQLI.class.getDeclaredField("userMapper");
        f.setAccessible(true);
        f.set(controller, mapper);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private static void login(String name, String role) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(name, "n/a", AuthorityUtils.createAuthorityList(role)));
    }

    @Test
    public void userGetsOwnName() {
        login("alice", "ROLE_USER");
        assertEquals("alice", controller.resolveAuthorizedUsername("alice"));
    }

    @Test(expected = AccessDeniedException.class)
    public void userCannotReferenceOtherUser() {
        login("alice", "ROLE_USER");
        controller.resolveAuthorizedUsername("bob");
    }

    @Test
    public void adminResolvesOtherUserThroughMapper() {
        login("root", "ROLE_ADMIN");
        assertEquals("bob", controller.resolveAuthorizedUsername("bob"));
    }

    @Test
    public void adminUnknownUserResolvesToNull() {
        login("root", "ROLE_ADMIN");
        assertNull(controller.resolveAuthorizedUsername("nobody"));
    }

    @Test(expected = AccessDeniedException.class)
    public void unauthenticatedDenied() {
        SecurityContextHolder.clearContext();
        controller.resolveAuthorizedUsername("alice");
    }
}
