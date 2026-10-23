package org.joychou.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * RASP：Hook java/io/ObjectInputStream类的resolveClass方法
 * RASP: https://github.com/baidu/openrasp/blob/master/agent/java/engine/src/main/java/com/baidu/openrasp/hook/DeserializationHook.java
 *
 * Run main method to test.
 */
public class AntObjectInputStream extends ObjectInputStream {

    protected final Logger logger= LoggerFactory.getLogger(AntObjectInputStream.class);

    /** Maximum object graph depth and number of references permitted during deserialization. */
    private static final long MAX_DEPTH = 5;
    private static final long MAX_REFERENCES = 100;
    private static final long MAX_BYTES = 1024 * 1024; // 1 MB

    public AntObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
        installObjectInputFilter();
    }

    /**
     * Install an ObjectInputFilter (Java 9+ API, backported to 8u121+ as sun.misc.ObjectInputFilter)
     * to restrict deserialization before readObject reaches resolveClass.
     */
    private void installObjectInputFilter() {
        // Try Java 9+ API first, then fall back to Java 8 sun.misc backport
        try {
            // Java 9+: java.io.ObjectInputFilter
            Class<?> filterClass = Class.forName("java.io.ObjectInputFilter");
            Class<?> configClass = Class.forName("java.io.ObjectInputFilter$Config");
            Object filter = configClass.getMethod("createFilter", String.class)
                    .invoke(null, buildFilterPattern());
            ObjectInputStream.class.getMethod("setObjectInputFilter", filterClass)
                    .invoke(this, filter);
            logger.info("Installed java.io.ObjectInputFilter for deserialization protection");
            return;
        } catch (Exception ignored) {
            // Not Java 9+, try sun.misc backport
        }
        try {
            // Java 8u121+: sun.misc.ObjectInputFilter
            Class<?> filterClass = Class.forName("sun.misc.ObjectInputFilter");
            Class<?> configClass = Class.forName("sun.misc.ObjectInputFilter$Config");
            Object filter = configClass.getMethod("createFilter", String.class)
                    .invoke(null, buildFilterPattern());
            configClass.getMethod("setObjectInputFilter", ObjectInputStream.class, filterClass)
                    .invoke(null, this, filter);
            logger.info("Installed sun.misc.ObjectInputFilter for deserialization protection");
        } catch (Exception e) {
            logger.warn("ObjectInputFilter not available on this JVM — relying on resolveClass allowlist only");
        }
    }

    /**
     * Build a JEP 290 filter pattern string that allowlists only safe classes
     * and rejects everything else.
     */
    private static String buildFilterPattern() {
        StringBuilder sb = new StringBuilder();
        sb.append("maxdepth=").append(MAX_DEPTH).append(";");
        sb.append("maxrefs=").append(MAX_REFERENCES).append(";");
        sb.append("maxbytes=").append(MAX_BYTES).append(";");
        for (String allowed : ALLOWED_CLASSES) {
            sb.append(allowed).append(";");
        }
        sb.append("!*");  // reject everything not explicitly allowed
        return sb.toString();
    }

    /**
     * Allowlist-based deserialization filter.
     * Only classes in ALLOWED_CLASSES (and Java primitives / arrays of allowed types) may be deserialized.
     * This replaces the former blacklist approach which was too easy to bypass with new gadget chains.
     */
    private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
            "org.joychou.security.AntObjectInputStream$MyObject",
            "org.joychou.dao.User",
            "java.lang.String",
            "java.lang.Number",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Double",
            "java.lang.Float",
            "java.lang.Boolean",
            "java.lang.Byte",
            "java.lang.Short",
            "java.lang.Character",
            "java.util.ArrayList",
            "java.util.HashMap",
            "java.util.LinkedHashMap",
            "java.util.HashSet",
            "java.util.Date"
    ));

    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
    {
        String className = desc.getName();

        logger.info("Deserialize class name: " + className);

        // Allow primitive types and arrays of allowed types
        if (!className.startsWith("[") && !ALLOWED_CLASSES.contains(className)) {
            throw new InvalidClassException("Unauthorized deserialization attempt — class not in allowlist", className);
        }

        return super.resolveClass(desc);
    }

    public static void main(String args[]) throws Exception{
        // 定义myObj对象
        MyObject myObj = new MyObject();
        myObj.name = "world";

        // 创建一个包含对象进行反序列化信息的/tmp/object数据文件
        FileOutputStream fos = new FileOutputStream("/tmp/object");
        ObjectOutputStream os = new ObjectOutputStream(fos);

        // writeObject()方法将myObj对象写入/tmp/object文件
        os.writeObject(myObj);
        os.close();

        // 从文件中反序列化obj对象
        FileInputStream fis = new FileInputStream("/tmp/object");
        AntObjectInputStream ois = new AntObjectInputStream(fis);  // AntObjectInputStream class

        //恢复对象即反序列化
        MyObject objectFromDisk = (MyObject)ois.readObject();
        System.out.println(objectFromDisk.name);
        ois.close();
    }

    static class  MyObject implements Serializable {
        public String name;
    }
}


