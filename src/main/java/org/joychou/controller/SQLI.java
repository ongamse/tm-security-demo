package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.sql.*;
import java.util.Arrays;
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

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_]{1,32}$");

    private static final List<String> ORDER_BY_COLUMNS = Arrays.asList("id", "username", "password");

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
    public String jdbc_sqli_vul(@RequestParam("username") String username, HttpServletRequest request) {

        // IDOR check: only the authenticated principal's own record (or an ADMIN) may be requested
        Principal callerPrincipal = request.getUserPrincipal();
        if (callerPrincipal == null || username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new AccessDeniedException("Access denied");
        }
        if (!request.isUserInRole("ADMIN") && !username.equals(callerPrincipal.getName())) {
            throw new AccessDeniedException("Access denied");
        }

        StringBuilder result = new StringBuilder();

        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // bind the user input as a parameter instead of concatenating it
            String sql = "select * from users where username = ?";
            PreparedStatement statement = con.prepareStatement(sql);
            statement.setString(1, username);
            logger.info(statement.toString());
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

        authorizeUsernameReference(request, username);
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
     * <p>Incorrect use of prepareStatement. PrepareStatement must use ? as a placeholder.</p>
     * <a href="http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a">http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a</a>
     */
    @RequestMapping("/jdbc/ps/vuln")
    public String jdbc_ps_vuln(@RequestParam("username") String username, HttpServletRequest request) {

        // IDOR check: only the authenticated principal's own record (or an ADMIN) may be requested
        Principal callerPrincipal = request.getUserPrincipal();
        if (callerPrincipal == null || username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new AccessDeniedException("Access denied");
        }
        if (!request.isUserInRole("ADMIN") && !username.equals(callerPrincipal.getName())) {
            throw new AccessDeniedException("Access denied");
        }

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
        authorizeUsernameReference(request, username);
        return userMapper.findByUserNameVuln01(username);
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public List<User> mybatisVuln02(@RequestParam("username") String username, HttpServletRequest request) {
        authorizeUsernameReference(request, username);
        return userMapper.findByUserNameVuln02(username);
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
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec01?username=joychou">http://localhost:8080/sqli/mybatis/sec01?username=joychou</a>
     */
    @GetMapping("/mybatis/sec01")
    public User mybatisSec01(@RequestParam("username") String username, HttpServletRequest request) {
        authorizeUsernameReference(request, username);
        return userMapper.findByUserName(username);
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public User mybatisSec02(@RequestParam("id") Integer id, HttpServletRequest request) {
        // IDOR check: only the authenticated principal's own record (or an ADMIN) may be returned
        Principal callerPrincipal = request.getUserPrincipal();
        if (callerPrincipal == null || id == null) {
            throw new AccessDeniedException("Access denied");
        }
        User record = userMapper.findById(id);
        if (record == null) {
            return null;
        }
        if (!request.isUserInRole("ADMIN") && !callerPrincipal.getName().equals(record.getUsername())) {
            throw new AccessDeniedException("Access denied");
        }
        return record;
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
        return userMapper.findByUserNameVuln03(orderByColumn(SecurityUtil.sqlFilter(sort)));
    }

    /**
     * Authorize a user-supplied username used as a direct reference to a users row.
     * Only the authenticated principal's own record may be requested, unless the caller has ROLE_ADMIN.
     * Fails closed (403 via Spring Security's access denied handling).
     */
    private static void authorizeUsernameReference(HttpServletRequest request, String username) {
        Principal principal = request.getUserPrincipal();
        if (principal == null || username == null) {
            throw new AccessDeniedException("Access denied");
        }
        if (request.isUserInRole("ADMIN")) {
            return;
        }
        byte[] expected = principal.getName().getBytes(StandardCharsets.UTF_8);
        byte[] actual = username.getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new AccessDeniedException("Access denied");
        }
    }

    /**
     * ORDER BY columns cannot be bound with #{}, so only allow known column names.
     *
     * @return the matching column name, or null (no ordering) if not allowlisted
     */
    private static String orderByColumn(String sort) {
        if (sort == null) {
            return null;
        }
        for (String column : ORDER_BY_COLUMNS) {
            if (column.equalsIgnoreCase(sort)) {
                return column;
            }
        }
        return null;
    }

}
