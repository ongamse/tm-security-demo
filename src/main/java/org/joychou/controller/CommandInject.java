package org.joychou.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.util.HtmlUtils;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String BAD_REQUEST = "Bad boy. I got u.";

    /** Directory whose content (and sub directories) may be listed. */
    @Value("${joychou.security.command.list.base:/tmp}")
    private String listBase;

    /** Server-side host entries (exact Host header values) that /codeinject/host may fetch. */
    @Value("${joychou.security.command.curl.allowed.hosts:localhost,localhost:8080}")
    private String[] curlAllowedHosts;

    /**
     * http://localhost:8080/codeinject?filepath=xxx
     * Lists a directory below the configured base directory; no process is started.
     *
     * @param filepath filepath relative to the base directory
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {
        return listDirectory(filepath);
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     *
     * The Host header only selects an entry of the server-side allowlist by exact equality;
     * the curl argv is built from constants and the configured entry, never the header.
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String requestedHost = request.getHeader("host");
        String configuredHost = null;
        if (curlAllowedHosts != null) {
            for (String entry : curlAllowedHosts) {
                String candidate = entry == null ? "" : entry.trim();
                if (!candidate.isEmpty() && !candidate.startsWith("-") && candidate.equals(requestedHost)) {
                    configuredHost = candidate;
                    break;
                }
            }
        }
        if (configuredHost == null) {
            return BAD_REQUEST;
        }
        logger.info("codeinject host: {}", configuredHost);
        List<String> cmdList = new ArrayList<String>();
        cmdList.add("curl");
        cmdList.add("-s");
        cmdList.add("--max-time");
        cmdList.add("5");
        cmdList.add("--proto");
        cmdList.add("=http,https");
        cmdList.add("--");
        cmdList.add(configuredHost);
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        try {
            return HtmlUtils.htmlEscape(WebUtils.convertStreamToString(process.getInputStream()));
        } finally {
            process.destroy();
        }
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        return listDirectory(filepath);
    }

    /**
     * An "ls -la" like listing implemented with java.nio. The requested path is resolved against
     * the configured base directory and must stay inside it after symbolic links are resolved.
     */
    private String listDirectory(String requested) throws IOException {
        if (requested == null || requested.isEmpty() || requested.length() > 1024) {
            return BAD_REQUEST;
        }
        Path base;
        Path target;
        try {
            base = Paths.get(listBase).toRealPath();
            target = base.resolve(requested).normalize().toRealPath();
        } catch (InvalidPathException e) {
            return BAD_REQUEST;
        } catch (IOException e) {
            return BAD_REQUEST;
        }
        if (!target.startsWith(base)) {
            return BAD_REQUEST;
        }

        List<Path> entries = new ArrayList<Path>();
        if (Files.isDirectory(target)) {
            DirectoryStream<Path> stream = Files.newDirectoryStream(target);
            try {
                for (Path entry : stream) {
                    entries.add(entry);
                }
            } finally {
                stream.close();
            }
            Collections.sort(entries);
        } else {
            entries.add(target);
        }

        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        StringBuilder out = new StringBuilder();
        for (Path entry : entries) {
            BasicFileAttributes attrs = Files.readAttributes(entry, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            Path name = entry.getFileName();
            out.append(attrs.isDirectory() ? 'd' : (attrs.isSymbolicLink() ? 'l' : '-')).append(' ')
                    .append(attrs.size()).append(' ')
                    .append(format.format(new Date(attrs.lastModifiedTime().toMillis()))).append(' ')
                    .append(name == null ? "" : name.toString()).append('\n');
        }
        return HtmlUtils.htmlEscape(out.toString());
    }
}
