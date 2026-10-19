package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;


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
            return HtmlUtils.htmlEscape(ob.get("name").toString());
        } catch (Exception e) {
            return HtmlUtils.htmlEscape(e.toString());
        }
    }

    public static void main(String[] args) {
        // Load exploit demo payload from external resource file instead of hardcoding
        String payload;
        try (InputStream is = Fastjson.class.getClassLoader().getResourceAsStream("fastjson_test_payload.txt");
             Scanner scanner = new Scanner(is, StandardCharsets.UTF_8.name())) {
            payload = scanner.useDelimiter("\\A").next();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load fastjson test payload from resource", e);
        }
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }
}
