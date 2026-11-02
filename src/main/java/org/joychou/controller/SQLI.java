package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;


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

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");

    @Value("${spring.datasource.url}")
    private String url;

    @Value("${spring.datasource.username}")
    private String user;

    @Value("${spring.datasource.password}")
    private String password;

    @Resource
    private UserMapper userMapper;


    /**
     * <p>Sql injection jbdc vuln code.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/vuln?username=joychou">http://localhost:8080/sqli/jdbc/vuln?username=joychou</a>
     */
    @RequestMapping("/jdbc/vuln")
    public String jdbc_sqli_vul(@RequestParam("username") String username) {

        StringBuilder result = new StringBuilder();

        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // bound parameter instead of string concatenation
            String sql = "select * from users where username = ?";
            PreparedStatement statement = con.prepareStatement(sql);
            statement.setString(1, username);
            logger.info(sql);
            ResultSet rs = statement.executeQuery();

            while (rs.next()) {
                String res_name = rs.getString("username");
                String res_pwd = rs.getString("password");
                String info = String.format("%s: %s\n", res_name, res_pwd);
                result.append(info);
                logger.info(info);
            }
            rs.close();
            con.close();


        } catch (ClassNotFoundException e) {
            logger.error("Sorry, can't find the Driver!");
        } catch (SQLException e) {
            logger.error(e.toString());
        }
        return result.toString();
    }


    /**
     * <p>Sql injection jbdc security code by using {@link PreparedStatement}.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/sec?username=joychou">http://localhost:8080/sqli/jdbc/sec?username=joychou</a>
     */
    @RequestMapping("/jdbc/sec")
    public String jdbc_sqli_sec(@RequestParam("username") String username, HttpServletRequest request) {

        authorizeUserReference(request, username);

        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // fix code
            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, username);

            logger.info(st.toString());  // sql after prepare statement
            ResultSet rs = st.executeQuery();

            while (rs.next()) {
                // only return the fields needed; never expose the stored password
                String res_name = rs.getString("username");
                String info = String.format("%s\n", res_name);
                result.append(info);
                logger.info(info);
            }

            rs.close();
            con.close();

        } catch (ClassNotFoundException e) {
            logger.error("Sorry, can't find the Driver!");
            e.printStackTrace();
        } catch (SQLException e) {
            logger.error(e.toString());
        }
        return result.toString();
    }


    /**
     * <p>Incorrect use of prepareStatement. PrepareStatement must use ? as a placeholder.</p>
     * <a href="http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a">http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a</a>
     */
    @RequestMapping("/jdbc/ps/vuln")
    public String jdbc_ps_vuln(@RequestParam("username") String username) {

        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connecting to Database successfully.");

            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, username);

            logger.info(st.toString());
            ResultSet rs = st.executeQuery();

            while (rs.next()) {
                String res_name = rs.getString("username");
                String res_pwd = rs.getString("password");
                String info = String.format("%s: %s\n", res_name, res_pwd);
                result.append(info);
                logger.info(info);
            }

            rs.close();
            con.close();

        } catch (ClassNotFoundException e) {
            logger.error("Sorry, can't find the Driver!");
            e.printStackTrace();
        } catch (SQLException e) {
            logger.error(e.toString());
        }
        return result.toString();
    }


    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1</a>
     * <p>select * from users where username = 'joychou' or '1'='1' </p>
     */
    @GetMapping("/mybatis/vuln01")
    public List<User> mybatisVuln01(@RequestParam("username") String username, HttpServletRequest request) {
        authorizeUserReference(request, username);
        return withoutPasswords(userMapper.findByUserNameVuln01(username));
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public List<User> mybatisVuln02(@RequestParam("username") String username, HttpServletRequest request) {
        validateUsernameFormat(username);
        List<User> found = userMapper.findByUserNameVuln02(username);
        // fuzzy search: only records the caller owns (or all, for admins) may be returned
        List<User> visible = new ArrayList<>();
        for (User u : found) {
            if (isOwnerOrAdmin(request, u.getUsername())) {
                visible.add(u);
            }
        }
        return withoutPasswords(visible);
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--">http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--</a>
     * <p> select * from users order by id desc-- asc</p>
     */
    @GetMapping("/mybatis/orderby/vuln03")
    public List<User> mybatisVuln03(@RequestParam("sort") String sort) {
        return userMapper.findByUserNameVuln03(allowedOrderColumn(sort));
    }


    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec01?username=joychou">http://localhost:8080/sqli/mybatis/sec01?username=joychou</a>
     */
    @GetMapping("/mybatis/sec01")
    public User mybatisSec01(@RequestParam("username") String username, HttpServletRequest request) {
        authorizeUserReference(request, username);
        return withoutPassword(userMapper.findByUserName(username));
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public User mybatisSec02(@RequestParam("id") Integer id, HttpServletRequest request) {
        User found = userMapper.findById(id);
        if (found == null) {
            return null;
        }
        // id is a direct object reference: caller must own the record (or be admin)
        authorizeUserReference(request, found.getUsername());
        return withoutPassword(found);
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
        return userMapper.findByUserNameVuln03(allowedOrderColumn(sort));
    }

    /**
     * Map user supplied sort key to a known column name (allowlist).
     * Returns null (no ordering) for anything not on the allowlist.
     */
    private static String allowedOrderColumn(String sort) {
        if ("id".equals(sort)) {
            return "id";
        }
        if ("username".equals(sort)) {
            return "username";
        }
        return null;
    }

    /**
     * Allowlist for a username reference (letters, digits, '_', '.', '-').
     */
    private static void validateUsernameFormat(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new InvalidReferenceException();
        }
    }

    /**
     * True when the authenticated caller is the referenced user or has the ADMIN role.
     */
    private static boolean isOwnerOrAdmin(HttpServletRequest request, String referencedUsername) {
        Principal principal = request.getUserPrincipal();
        if (principal == null || referencedUsername == null) {
            return false;
        }
        return referencedUsername.equals(principal.getName()) || request.isUserInRole("ADMIN");
    }

    /**
     * Validate the reference format and enforce ownership; fail closed with 403.
     */
    private static void authorizeUserReference(HttpServletRequest request, String username) {
        validateUsernameFormat(username);
        if (!isOwnerOrAdmin(request, username)) {
            throw new ReferenceAccessDeniedException();
        }
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "invalid username")
    private static class InvalidReferenceException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    @ResponseStatus(value = HttpStatus.FORBIDDEN, reason = "access denied")
    private static class ReferenceAccessDeniedException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static User withoutPassword(User u) {
        if (u != null) {
            u.setPassword(null);
        }
        return u;
    }

    private static List<User> withoutPasswords(List<User> users) {
        if (users != null) {
            for (User u : users) {
                withoutPassword(u);
            }
        }
        return users;
    }

}
