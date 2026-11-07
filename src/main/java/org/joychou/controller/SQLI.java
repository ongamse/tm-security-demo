package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
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
     * Thrown when the authenticated caller references a record that is not their own.
     */
    @ResponseStatus(HttpStatus.FORBIDDEN)
    private static class ForbiddenReferenceException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    /**
     * A caller may only reference their own record (matched by username); admins may reference any record.
     */
    private static boolean isSelfOrAdmin(HttpServletRequest request, String username) {
        Principal principal = request.getUserPrincipal();
        if (principal == null || username == null) {
            return false;
        }
        return principal.getName().equals(username) || request.isUserInRole("ADMIN");
    }

    private static void requireSelfOrAdmin(HttpServletRequest request, String username) {
        if (!isSelfOrAdmin(request, username)) {
            throw new ForbiddenReferenceException();
        }
    }

    /**
     * The lookup reference is the authenticated principal, never the request value. A request supplied
     * username is only accepted when it equals the authenticated username; anything else is 403.
     */
    private static String authenticatedUsername(HttpServletRequest request, String requestedUsername) {
        Principal principal = request.getUserPrincipal();
        if (principal == null || principal.getName() == null) {
            throw new ForbiddenReferenceException();
        }
        String authenticated = principal.getName();
        if (requestedUsername != null && !authenticated.equals(requestedUsername)) {
            throw new ForbiddenReferenceException();
        }
        return authenticated;
    }


    /**
     * <p>Sql injection jbdc vuln code.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/vuln?username=joychou">http://localhost:8080/sqli/jdbc/vuln?username=joychou</a>
     */
    @RequestMapping("/jdbc/vuln")
    public String jdbc_sqli_vul(HttpServletRequest request,
                                @RequestParam(value = "username", required = false) String requestedUsername) {

        String username = authenticatedUsername(request, requestedUsername);
        StringBuilder result = new StringBuilder();

        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connect to database successfully.");

            // sqli vuln code
            String sql = "select * from users where username = ?";
            PreparedStatement statement = con.prepareStatement(sql);
            statement.setString(1, username);
            logger.info("Executing parameterized user query");
            ResultSet rs = statement.executeQuery();

            while (rs.next()) {
                String res_name = rs.getString("username");
                String res_pwd = rs.getString("password");
                String info = String.format("%s: %s\n", res_name, res_pwd);
                result.append(info);
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
    public String jdbc_sqli_sec(HttpServletRequest request, @RequestParam("username") String username) {

        requireSelfOrAdmin(request, username);
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

            logger.info("Executing parameterized user query");
            ResultSet rs = st.executeQuery();

            while (rs.next()) {
                String res_name = rs.getString("username");
                String res_pwd = rs.getString("password");
                String info = String.format("%s: %s\n", res_name, res_pwd);
                result.append(info);
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
    public String jdbc_ps_vuln(HttpServletRequest request,
                               @RequestParam(value = "username", required = false) String requestedUsername) {

        String username = authenticatedUsername(request, requestedUsername);
        StringBuilder result = new StringBuilder();
        try {
            Class.forName(driver);
            Connection con = DriverManager.getConnection(url, user, password);

            if (!con.isClosed())
                System.out.println("Connecting to Database successfully.");

            String sql = "select * from users where username = ?";
            PreparedStatement st = con.prepareStatement(sql);
            st.setString(1, username);

            logger.info("Executing parameterized user query");
            ResultSet rs = st.executeQuery();

            while (rs.next()) {
                String res_name = rs.getString("username");
                String res_pwd = rs.getString("password");
                String info = String.format("%s: %s\n", res_name, res_pwd);
                result.append(info);
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
    public List<User> mybatisVuln01(HttpServletRequest request, @RequestParam("username") String username) {
        requireSelfOrAdmin(request, username);
        return userMapper.findByUserNameVuln01(username);
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public List<User> mybatisVuln02(HttpServletRequest request, @RequestParam("username") String username) {
        requireSelfOrAdmin(request, username);
        // LIKE matching can also hit other users' rows; only return records the caller may access.
        return userMapper.findByUserNameVuln02(username).stream()
                .filter(u -> isSelfOrAdmin(request, u.getUsername()))
                .collect(Collectors.toList());
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
    public User mybatisSec01(HttpServletRequest request, @RequestParam("username") String username) {
        requireSelfOrAdmin(request, username);
        return userMapper.findByUserName(username);
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public User mybatisSec02(HttpServletRequest request, @RequestParam("id") Integer id) {
        User found = userMapper.findById(id);
        // Ownership check: the referenced record must belong to the caller (or caller is admin).
        if (found != null) {
            requireSelfOrAdmin(request, found.getUsername());
        }
        return found;
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
