package org.joychou.util;

import com.alibaba.fastjson.JSON;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

public class LoginUtils {

    // get current login username
    public static String getUserInfo2JsonStr(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        Map<String, String> m = new HashMap<>();
        // no principal (e.g. cross-origin request without cookies): return an empty object instead of an NPE
        if (principal != null) {
            m.put("Username", principal.getName());
        }

        return JSON.toJSONString(m);
    }
}
