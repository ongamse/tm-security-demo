package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.sql.*;
import java.util.List;
import java.util.stream.Collectors;


/**
 * SQL Injection
 *
 * @author JoyChou @2018.08.22
 */

@SuppressWarnings("Duplicates")
@RestController
@RequestMapping("/sqli")
public class SQLI {

    private static final Logger logger = LoggerFactory.getLogger(SQLI.class);

    // com.mysql.jdbc.Driver is deprecated. Change to com.mysql.cj.jdbc.Driver.
    private static final String driver = "com.mysql.cj.jdbc.Driver";

    @Value("${spring.datasource.url}")
    private String url;

    @Value("${spring.datasource.username}")
    private String user;

    @Value("${spring.datasource.password}")
    private String password;

    @Resource
    private UserMapper userMapper;

    /**
     * Name of the authenticated caller, or null when there is none.
     */
    private static String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return null;
        }
        return auth.getName();
    }

    private static boolean isCurrentUser(String username) {
        String current = currentUsername();
        return current != null && current.equals(username);
    }

    private static boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return false;
        }
        for (GrantedAuthority a : auth.getAuthorities()) {
            if ("ROLE_ADMIN".equals(a.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    private static class UnauthenticatedException extends RuntimeException {
        UnauthenticatedException() {
            super("Authentication required");
        }
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    private static class ForbiddenLookupException extends RuntimeException {
        ForbiddenLookupException() {
            super("Access denied");
        }
    }

    /**
     * Lookup key for user queries. It is always the server-owned name of the authenticated
     * principal, never the request string. A request username is accepted only for backwards
     * compatibility and only when it names the caller.
     *
     * @param requested username supplied by the client (may be null)
     * @return the authenticated principal's name
     * @throws UnauthenticatedException (401) when there is no authenticated principal
     * @throws ForbiddenLookupException (403) when the requested username is not the caller
     */
    private static String lookupKey(String requested) {
        String current = currentUsername();
        if (current == null) {
            throw new UnauthenticatedException();
        }
        if (requested != null && !requested.equals(current)) {
            throw new ForbiddenLookupException();
        }
        return current;
    }

    /**
     * Returns a copy of the user without the password (hash).
     */
    private static User redact(User u) {
        if (u == null) {
            return null;
        }
        User copy = new User();
        copy.setId(u.getId());
        copy.setUsername(u.getUsername());
        return copy;
    }

    private static List<User> redact(List<User> users) {
        return users.stream().map(SQLI::redact).collect(Collectors.toList());
    }


    /**
     * <p>Sql injection jbdc vuln code.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/vuln?username=joychou">http://localhost:8080/sqli/jdbc/vuln?username=joychou</a>
     */
    @RequestMapping("/jdbc/vuln")
    public String jdbc_sqli_vul(@RequestParam("username") String username) {

        // The lookup key is the authenticated principal, not the request string.
        final String owner = lookupKey(username);
        StringBuilder result = new StringBuilder();

        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // sqli vuln code
            String sql = "select * from users where username = ?";
            PreparedStatement statement = con.prepareStatement(sql);
            statement.setString(1, owner);
            logger.info("Executing prepared statement");
            ResultSet rs = statement.executeQuery();

            while (rs.next()) {
                // Never return the stored password (hash) to the caller.
                String res_name = rs.getString("username");
                String info = String.format("%s\n", res_name);
                result.append(info);
                logger.info("Query result row read");
            }
            rs.close();
            con.close();


        } catch (ClassNotFoundException e) {
            logger.error("Sorry, can't find the Driver!");
        } catch (SQLException e) {
            logger.error("SQL execution failed", e);
        }
        return result.toString();
    }


    /**
     * <p>Sql injection jbdc security code by using {@link PreparedStatement}.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/sec?username=joychou">http://localhost:8080/sqli/jdbc/sec?username=joychou</a>
     */
    @RequestMapping("/jdbc/sec")
    public String jdbc_sqli_sec(@RequestParam("username") String username) {

        final String owner = lookupKey(username);
        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // fix code
            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, owner);

            logger.info("Executing prepared statement");
            ResultSet rs = st.executeQuery();

            while (rs.next()) {
                // Never return the stored password (hash) to the caller.
                String res_name = rs.getString("username");
                String info = String.format("%s\n", res_name);
                result.append(info);
                logger.info("Query result row read");
            }

            rs.close();
            con.close();

        } catch (ClassNotFoundException e) {
            logger.error("Sorry, can't find the Driver!");
            e.printStackTrace();
        } catch (SQLException e) {
            logger.error("SQL execution failed", e);
        }
        return result.toString();
    }


    /**
     * <p>Incorrect use of prepareStatement. PrepareStatement must use ? as a placeholder.</p>
     * <a href="http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a">http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a</a>
     */
    @RequestMapping("/jdbc/ps/vuln")
    public String jdbc_ps_vuln(@RequestParam("username") String username) {

        // The lookup key is the authenticated principal, not the request string.
        final String owner = lookupKey(username);
        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connecting to Database successfully.");

            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, owner);

            logger.info("Executing prepared statement");
            ResultSet rs = st.executeQuery();

            while (rs.next()) {
                // Never return the stored password (hash) to the caller.
                String res_name = rs.getString("username");
                String info = String.format("%s\n", res_name);
                result.append(info);
                logger.info("Query result row read");
            }

            rs.close();
            con.close();

        } catch (ClassNotFoundException e) {
            logger.error("Sorry, can't find the Driver!");
            e.printStackTrace();
        } catch (SQLException e) {
            logger.error("SQL execution failed", e);
        }
        return result.toString();
    }


    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1</a>
     * <p>select * from users where username = 'joychou' or '1'='1' </p>
     */
    @GetMapping("/mybatis/vuln01")
    public List<User> mybatisVuln01(@RequestParam("username") String username) {
        return redact(userMapper.findByUserNameVuln01(lookupKey(username)));
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public List<User> mybatisVuln02(@RequestParam("username") String username) {
        // The lookup key is the authenticated principal, not the request string.
        return redact(userMapper.findByUserNameVuln02(lookupKey(username)));
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--">http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--</a>
     * <p> select * from users order by id desc-- asc</p>
     */
    @GetMapping("/mybatis/orderby/vuln03")
    public List<User> mybatisVuln03(@RequestParam("sort") String sort) {
        return userMapper.findByUserNameVuln03(orderByColumn(sort));
    }

    /**
     * Allowlist of sortable columns. ORDER BY identifiers cannot be bound as
     * parameters, so only a fixed, known column name is ever passed on.
     *
     * @return the allowlisted column name, or null (no ordering) if not allowed
     */
    private static String orderByColumn(String sort) {
        if (sort == null) {
            return null;
        }
        switch (sort.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "id":
                return "id";
            case "username":
                return "username";
            case "password":
                return "password";
            default:
                return null;
        }
    }


    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec01?username=joychou">http://localhost:8080/sqli/mybatis/sec01?username=joychou</a>
     */
    @GetMapping("/mybatis/sec01")
    public User mybatisSec01(@RequestParam("username") String username) {
        return redact(userMapper.findByUserName(lookupKey(username)));
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public User mybatisSec02(@RequestParam("id") Integer id) {
        User found = userMapper.findById(id);
        if (!isAdmin() && (found == null || !isCurrentUser(found.getUsername()))) {
            throw new AccessDeniedException("Access denied");
        }
        return redact(found);
    }


    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec03">http://localhost:8080/sqli/mybatis/sec03</a>
     */
    @GetMapping("/mybatis/sec03")
    public User mybatisSec03() {
        return userMapper.OrderByUsername();
    }

    /**
     * <p>Order by sql injection mybatis security code by using sql filter.</p>
     * <a href="http://localhost:8080/sqli/mybatis/orderby/sec04?sort=id">http://localhost:8080/sqli/mybatis/orderby/sec04?sort=id</a>
     * <p>select * from users order by id asc </p>
     */
    @GetMapping("/mybatis/orderby/sec04")
    public List<User> mybatisOrderBySec04(@RequestParam("sort") String sort) {
        return userMapper.findByUserNameVuln03(orderByColumn(sort));
    }

}
