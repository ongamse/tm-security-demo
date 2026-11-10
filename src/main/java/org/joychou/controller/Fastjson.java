package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import org.joychou.util.WebUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;


@Controller
@RequestMapping("/fastjson")
public class Fastjson {

    @RequestMapping(value = "/deserialize", method = {RequestMethod.POST})
    @ResponseBody
    public String Deserialize(@RequestBody String params) {
        // 如果Content-Type不设置application/json格式，post数据会被url编码
        try {
            // 将post提交的string转换为json
            JSONObject ob = JSON.parseObject(params);
            return WebUtils.escapeHtml(ob.get("name").toString());
        } catch (Exception e) {
            return WebUtils.escapeHtml(e.toString());
        }
    }

    public static void main(String[] args) {
        // Open calc in mac
        // Note: the PoC payload (public sample class file, not a credential) is loaded from a classpath resource.
        String payload = loadPayload();
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }

    private static String loadPayload() {
        try (InputStream in = Fastjson.class.getResourceAsStream("/fastjson-poc-payload.txt")) {
            if (in == null) {
                throw new IllegalStateException("Missing classpath resource: fastjson-poc-payload.txt");
            }
            // The resource is line-wrapped for readability; line breaks are not part of the payload.
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
