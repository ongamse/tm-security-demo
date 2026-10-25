package org.joychou.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;


@Controller
@RequestMapping("/fastjson")
public class Fastjson {

    private static final Logger logger = LoggerFactory.getLogger(Fastjson.class);

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
        // Fastjson deserialization test payload — load from environment variable
        String payload = System.getenv("FASTJSON_TEST_PAYLOAD");
        if (payload == null || payload.isEmpty()) {
            logger.info("FASTJSON_TEST_PAYLOAD not configured, skipping parse");
            return;
        }
        JSON.parseObject(payload, Feature.SupportNonPublicField);
    }
}
