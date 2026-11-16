package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;


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
     * <p>Sql injection jbdc vuln code.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/vuln?username=joychou">http://localhost:8080/sqli/jdbc/vuln?username=joychou</a>
     */
    @RequestMapping("/jdbc/vuln")
    public String jdbc_sqli_vul(@RequestParam("username") String requestedUsername) {

        final String username = authorizedUsername(requestedUsername);
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
    public String jdbc_sqli_sec(@RequestParam("username") String username) {

        checkOwnerOrAdmin(username);
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
    public String jdbc_ps_vuln(@RequestParam("username") String requestedUsername) {

        final String username = authorizedUsername(requestedUsername);
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
    public List<User> mybatisVuln01(@RequestParam("username") String username) {
        checkOwnerOrAdmin(username);
        return userMapper.findByUserNameVuln01(username);
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public List<User> mybatisVuln02(@RequestParam("username") String requestedUsername) {
        // Authorize before any query. Only admins may search with a caller-chosen pattern;
        // everyone else searches with their own authenticated username.
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getName() == null) {
            throw new AccessDeniedException("Access is denied");
        }
        String username = isAdmin(auth) ? requestedUsername : auth.getName();
        // LIKE search can match other accounts: only return rows the caller is allowed to see.
        List<User> visible = new ArrayList<>();
        for (User u : userMapper.findByUserNameVuln02(username)) {
            if (isOwnerOrAdmin(auth, u.getUsername())) {
                visible.add(u);
            }
        }
        return visible;
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
    public User mybatisSec01(@RequestParam("username") String username) {
        checkOwnerOrAdmin(username);
        return userMapper.findByUserName(username);
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public User mybatisSec02(@RequestParam("id") Integer id) {
        User found = userMapper.findById(id);
        if (found != null) {
            checkOwnerOrAdmin(found.getUsername());
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
        return userMapper.findByUserNameVuln03(orderByColumn(sort));
    }

    /**
     * Allowlist of sortable columns. ORDER BY cannot be bound as a parameter,
     * so only known column names are ever passed to the mapper.
     *
     * @return the canonical column name, or null (no ordering) if not allowed
     */
    /**
     * Object-level authorization: a caller may only reference their own account,
     * unless they hold ROLE_ADMIN. Fails closed when nobody is authenticated.
     *
     * @throws AccessDeniedException (rendered as 403) when the caller does not own the account
     */
    private static void checkOwnerOrAdmin(String targetUsername) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!isOwnerOrAdmin(auth, targetUsername)) {
            throw new AccessDeniedException("Access is denied");
        }
    }

    private static boolean isOwnerOrAdmin(Authentication auth, String targetUsername) {
        if (auth == null || !auth.isAuthenticated() || auth.getName() == null) {
            return false;
        }
        if (isAdmin(auth)) {
            return true;
        }
        return targetUsername != null && auth.getName().equals(targetUsername);
    }

    private static boolean isAdmin(Authentication auth) {
        if (auth == null) {
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
     * Authorizes the request and returns the username that is actually queried.
     * The value comes from the authenticated principal; only ROLE_ADMIN may
     * query another account (the requested name is used for admins).
     *
     * @throws AccessDeniedException when nobody is authenticated or the caller does not own the account
     */
    private static String authorizedUsername(String requestedUsername) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!isOwnerOrAdmin(auth, requestedUsername)) {
            throw new AccessDeniedException("Access is denied");
        }
        return isAdmin(auth) ? requestedUsername : auth.getName();
    }

    private static String orderByColumn(String sort) {
        if (sort == null) {
            return null;
        }
        switch (sort.trim().toLowerCase(Locale.ROOT)) {
            case "id":
                return "id";
            case "username":
                return "username";
            default:
                return null;
        }
    }

}
