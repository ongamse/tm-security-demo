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

    protected final Logger logger= LoggerFactory.getLogger(AntObjectInputStream.class);

    public AntObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    /** Allowlist of safe class prefixes permitted during deserialization. */
    private static final String[] ALLOWED_CLASS_PREFIXES = {
            "org.joychou.",
            "java.lang.",
            "java.util.",
            "java.math.",
            "[B", // byte array
            "[C", // char array
            "[I", // int array
            "[J", // long array
            "[S", // short array
            "[D", // double array
            "[F", // float array
            "[Z"  // boolean array
    };

    /**
     * Allowlist-based type filtering for safe deserialization.
     * Only classes matching known-safe prefixes are permitted.
     */
    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
    {
        String className = desc.getName();

        logger.info("Deserialize class name: " + className);

        for (String allowed : ALLOWED_CLASS_PREFIXES) {
            if (className.startsWith(allowed)) {
                return super.resolveClass(desc);
            }
        }

        throw new InvalidClassException(
                "Deserialization of class not allowed by allowlist", className);
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


