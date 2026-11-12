package org.joychou.controller;


import org.joychou.mapper.UserMapper;
import org.joychou.dao.User;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
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

    @Value("${spring.datasource.url}")
    private String url;

    @Value("${spring.datasource.username}")
    private String user;

    @Value("${spring.datasource.password}")
    private String password;

    @Resource
    private UserMapper userMapper;

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");

    private static final String ADMIN_AUTHORITY = "ROLE_ADMIN";

    /** Authenticated username of the caller, or null when there is no authenticated principal. */
    private static String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return null;
        }
        return auth.getName();
    }

    private static boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (currentUsername() == null) {
            return false;
        }
        for (GrantedAuthority authority : auth.getAuthorities()) {
            if (ADMIN_AUTHORITY.equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    /** The caller may only reference its own record unless it has the ADMIN role. */
    private static boolean mayAccess(String username) {
        String caller = currentUsername();
        return caller != null && (caller.equals(username) || isAdmin());
    }

    /**
     * Validates the requested username format and binds it to the authenticated caller.
     *
     * @return null when the request may proceed, otherwise the error response to return.
     */
    private static ResponseEntity<String> guardUsername(String username) {
        if (username == null || !USERNAME_PATTERN.matcher(username).matches()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Bad Request");
        }
        if (!mayAccess(username)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden");
        }
        return null;
    }


    /**
     * <p>Sql injection jbdc vuln code.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/vuln?username=joychou">http://localhost:8080/sqli/jdbc/vuln?username=joychou</a>
     */
    @RequestMapping("/jdbc/vuln")
    public ResponseEntity<String> jdbc_sqli_vul(@RequestParam("username") String username) {

        ResponseEntity<String> denied = guardUsername(username);
        if (denied != null) {
            return denied;
        }

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

            // return only the username; do not expose the stored credential
            while (rs.next()) {
                String res_name = rs.getString("username");
                String info = String.format("%s\n", res_name);
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
        return ResponseEntity.ok(result.toString());
    }


    /**
     * <p>Sql injection jbdc security code by using {@link PreparedStatement}.</p><br>
     *
     * <a href="http://localhost:8080/sqli/jdbc/sec?username=joychou">http://localhost:8080/sqli/jdbc/sec?username=joychou</a>
     */
    @RequestMapping("/jdbc/sec")
    public ResponseEntity<String> jdbc_sqli_sec(@RequestParam("username") String username) {

        ResponseEntity<String> denied = guardUsername(username);
        if (denied != null) {
            return denied;
        }

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

            // return only the username; do not expose the stored credential
            while (rs.next()) {
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
        return ResponseEntity.ok(result.toString());
    }


    /**
     * <p>Incorrect use of prepareStatement. PrepareStatement must use ? as a placeholder.</p>
     * <a href="http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a">http://localhost:8080/sqli/jdbc/ps/vuln?username=joychou' or 'a'='a</a>
     */
    @RequestMapping("/jdbc/ps/vuln")
    public ResponseEntity<String> jdbc_ps_vuln(@RequestParam("username") String username) {

        ResponseEntity<String> denied = guardUsername(username);
        if (denied != null) {
            return denied;
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

            // return only the username; do not expose the stored credential
            while (rs.next()) {
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
        return ResponseEntity.ok(result.toString());
    }


    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1</a>
     * <p>select * from users where username = 'joychou' or '1'='1' </p>
     */
    @GetMapping("/mybatis/vuln01")
    public ResponseEntity<?> mybatisVuln01(@RequestParam("username") String username) {
        ResponseEntity<String> denied = guardUsername(username);
        if (denied != null) {
            return denied;
        }
        return ResponseEntity.ok(userMapper.findByUserNameVuln01(username));
    }

    /**
     * <p>Sql injection of mybatis vuln code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1">http://localhost:8080/sqli/mybatis/vuln02?username=joychou' or '1'='1</a>
     * <p>select * from users where username like '%joychou' or '1'='1%' </p>
     */
    @GetMapping("/mybatis/vuln02")
    public ResponseEntity<?> mybatisVuln02(@RequestParam("username") String username) {
        ResponseEntity<String> denied = guardUsername(username);
        if (denied != null) {
            return denied;
        }
        List<User> found = userMapper.findByUserNameVuln02(username);
        if (isAdmin()) {
            return ResponseEntity.ok(found);
        }
        // the LIKE match may hit other users; a non-admin caller only gets its own record
        String caller = currentUsername();
        List<User> own = new ArrayList<>();
        for (User u : found) {
            if (caller.equals(u.getUsername())) {
                own.add(u);
            }
        }
        return ResponseEntity.ok(own);
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
    public ResponseEntity<?> mybatisSec01(@RequestParam("username") String username) {
        ResponseEntity<String> denied = guardUsername(username);
        if (denied != null) {
            return denied;
        }
        return ResponseEntity.ok(userMapper.findByUserName(username));
    }

    /**
     * <p>Sql injection mybatis security code.</p>
     * <a href="http://localhost:8080/sqli/mybatis/sec02?id=1">http://localhost:8080/sqli/mybatis/sec02?id=1</a>
     */
    @GetMapping("/mybatis/sec02")
    public ResponseEntity<?> mybatisSec02(@RequestParam("id") Integer id) {
        User found = userMapper.findById(id);
        // the record must belong to the caller (admins may read any); unknown ids are
        // refused the same way for non-admins so ids cannot be enumerated
        if (found == null) {
            return isAdmin() ? ResponseEntity.ok().build()
                    : ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden");
        }
        if (!mayAccess(found.getUsername())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Forbidden");
        }
        return ResponseEntity.ok(found);
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
