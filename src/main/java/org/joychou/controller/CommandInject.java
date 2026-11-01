package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@RestController
public class CommandInject {

    /** Fixed base directory that listings are confined to. */
    private static final Path BASE_DIR = Paths.get(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize();

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * List a directory below the fixed base directory using java.nio (no process is spawned).
     *
     * @param filepath directory name relative to the base directory
     * @return listing, or an error message
     */
    private String listUnderBase(String filepath) {
        String filtered = SecurityUtil.cmdFilter(filepath);
        if (null == filtered) {
            return "Bad boy. I got u.";
        }
        try {
            Path target = BASE_DIR.resolve(filtered).normalize();
            if (!target.startsWith(BASE_DIR) || !Files.isDirectory(target)) {
                return "Bad boy. I got u.";
            }
            List<String> names = new ArrayList<>();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(target)) {
                for (Path entry : stream) {
                    names.add(entry.getFileName().toString());
                }
            }
            Collections.sort(names);
            return HtmlUtils.htmlEscape(String.join("\n", names));
        } catch (IOException | RuntimeException e) {
            logger.error("list failed: {}", e.getClass().getSimpleName());
            return "Command exec failed!!";
        }
    }

    /**
     * http://localhost:8080/codeinject?filepath=tmpdir
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) {
        return listUnderBase(filepath);
    }

    /**
     * Host header is only logged; no process is spawned with request data.
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) {
        String host = request.getHeader("host");
        logger.info("codeinject/host requested");
        return host == null ? "Bad boy. I got u." : "OK";
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) {
        return listUnderBase(filepath);
    }
}
