package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.sql.*;
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

    @Value("${spring.datasource.url}")
    private String url;

    @Value("${spring.datasource.username}")
    private String user;

    @Value("${spring.datasource.password}")
    private String password;

    @Resource
    private UserMapper userMapper;

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_]{1,64}$");

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    private static class InvalidReferenceException extends RuntimeException {
        InvalidReferenceException(String message) {
            super(message);
        }
    }

    /**
     * Validate a user-supplied username reference before it is used in a lookup. Fails closed.
     */
    private static String requireValidUsername(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            throw new InvalidReferenceException("Invalid username");
        }
        return username;
    }

    /**
     * Validate a user-supplied numeric id reference before it is used in a lookup. Fails closed.
     */
    private static Integer requireValidId(Integer id) {
        if (id == null || id < 1) {
            throw new InvalidReferenceException("Invalid id");
        }
        return id;
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    private static class ForbiddenReferenceException extends RuntimeException {
        ForbiddenReferenceException(String message) {
            super(message);
        }
    }

    /**
     * Name of the authenticated caller. Fails closed (403) when there is no authenticated principal.
     */
    private static String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken
                || auth.getName() == null) {
            throw new ForbiddenReferenceException("Access denied");
        }
        return auth.getName();
    }

    private static boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getAuthorities() == null) {
            return false;
        }
        for (GrantedAuthority authority : auth.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validate a requested username and authorize the caller for that user record: the caller must be
     * the record owner or hold ROLE_ADMIN. Fails closed with 403.
     */
    private static String requireAuthorizedUsername(String username) {
        String valid = requireValidUsername(username);
        String caller = currentUsername();
        if (!isAdmin() && !caller.equals(valid)) {
            throw new ForbiddenReferenceException("Access denied");
        }
        return valid;
    }


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

            // sqli vuln code
            String sql = "select * from users where username = ?";
            PreparedStatement statement = con.prepareStatement(sql);
            statement.setString(1, requireAuthorizedUsername(username));
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
    public String jdbc_sqli_sec(@RequestParam("username") String username) {

        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // fix code
            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, requireAuthorizedUsername(username));

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
    public String jdbc_ps_vuln(@RequestParam("username") String username) {

        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connecting to Database successfully.");

            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, requireAuthorizedUsername(username));

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
    public List<User> mybatisVuln01(@RequestParam("username") String username) {
        return userMapper.findByUserNameVuln01(requireAuthorizedUsername(username));
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public List<User> mybatisVuln02(@RequestParam("username") String username) {
        return userMapper.findByUserNameVuln02(requireAuthorizedUsername(username));
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--">http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--</a>
     * <p> select * from users order by id desc-- asc</p>
     */
    @GetMapping("/mybatis/orderby/vuln03")
    public List<User> mybatisVuln03(@RequestParam("sort") String sort) {
        return userMapper.findByUserNameVuln03(sort);
    }


    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec01?username=joychou">http://localhost:8080/sqli/mybatis/sec01?username=joychou</a>
     */
    @GetMapping("/mybatis/sec01")
    public User mybatisSec01(@RequestParam("username") String username) {
        return userMapper.findByUserName(requireAuthorizedUsername(username));
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public User mybatisSec02(@RequestParam("id") Integer id) {
        Integer validId = requireValidId(id);
        String caller = currentUsername();
        if (isAdmin()) {
            return userMapper.findById(validId);
        }
        // Indirect, caller-scoped lookup: a record owned by another user can never be returned.
        return userMapper.findByIdAndUsername(validId, caller);
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
        return userMapper.findByUserNameVuln03(SecurityUtil.sqlFilter(sort));
    }

}
