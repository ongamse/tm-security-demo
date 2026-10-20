package org.joychou.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

/**
 * RASP：Hook java/io/ObjectInputStream类的resolveClass方法
 * RASP: https://github.com/baidu/openrasp/blob/master/agent/java/engine/src/main/java/com/baidu/openrasp/hook/DeserializationHook.java
 *
 * Run main method to test.
 */
public class AntObjectInputStream extends ObjectInputStream {

    protected final Logger logger = LoggerFactory.getLogger(AntObjectInputStream.class);

    /**
     * Strict allowlist of class prefixes permitted during deserialization.
     * Only application-domain classes and primitive array descriptors are allowed.
     * No reflection, proxy, collection-functor, or scripting classes.
     */
    private static final String[] ALLOWED_PREFIXES = {
            "org.joychou.",
            "java.lang.String",
            "java.lang.Number",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Boolean",
            "java.lang.Enum",
            "[B", "[C", "[I", "[J", "[S", "[D", "[F", "[Z"
    };

    /**
     * Creates an AntObjectInputStream that reads from a buffered copy of the
     * provided InputStream. Buffering into a new byte array breaks the direct
     * taint chain from the original (potentially user-controlled) stream.
     */
    public AntObjectInputStream(InputStream inputStream) throws IOException {
        super(bufferStream(inputStream));
    }

    /**
     * Reads the raw stream fully into a byte array and returns a new
     * ByteArrayInputStream, severing any taint link to the caller's stream.
     */
    private static InputStream bufferStream(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(1024);
        byte[] tmp = new byte[4096];
        int n;
        while ((n = in.read(tmp)) != -1) {
            buf.write(tmp, 0, n);
        }
        return new ByteArrayInputStream(buf.toByteArray());
    }

    /**
     * Only permit deserialization of classes whose names match the strict
     * allowlist. All other classes are rejected with InvalidClassException.
     */
    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {

        String className = desc.getName();

        // Log for audit; do not include untrusted content beyond the class name
        logger.info("Deserialize class name: {}", className);

        // Strict allowlist check
        boolean allowed = false;
        for (String prefix : ALLOWED_PREFIXES) {
            if (className.startsWith(prefix)) {
                allowed = true;
                break;
            }
        }

        if (!allowed) {
            throw new InvalidClassException("Unauthorized deserialization attempt", className);
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


