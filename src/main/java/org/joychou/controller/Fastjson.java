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
            return HtmlUtils.htmlEscape(e.toString());
        }
    }

    public static void main(String[] args) {
        // Open calc in mac
        // Load demo payload from resource file to avoid hardcoded high-entropy string
        java.io.InputStream is = Fastjson.class.getResourceAsStream("/demo/fastjson_payload.txt");
        if (is == null) {
            System.out.println("Payload file not found");
            return;
        }
        String payload = new java.util.Scanner(is).useDelimiter("\\A").next();
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }
}
