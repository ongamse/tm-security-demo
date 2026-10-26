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
            return e.toString();
        }
    }

    public static void main(String[] args) {
        // Payload loaded from environment to avoid hardcoded high-entropy strings in source
        String payload = System.getenv("FASTJSON_TEST_PAYLOAD");
        if (payload == null || payload.isEmpty()) {
            System.err.println("Set FASTJSON_TEST_PAYLOAD environment variable with the JSON payload.");
            return;
        }
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }
}
