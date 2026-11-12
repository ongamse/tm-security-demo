package org.joychou.util;

import com.alibaba.fastjson.JSON;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

public class LoginUtils {

    // get current login username
    public static Map<String, String> getUserInfo(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        String username = principal.getName();
        Map<String, String> m = new HashMap<>();
        m.put("Username", username);
        return m;
    }

    public static String getUserInfo2JsonStr(HttpServletRequest request) {
        return JSON.toJSONString(getUserInfo(request));
    }
}
