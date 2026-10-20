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

    /**
     * Only allow deserialization of explicitly permitted classes (allowlist approach).
     *
     * Allowlist is more secure than denylist because it rejects unknown gadget classes
     * by default, rather than requiring each dangerous class to be enumerated.
     */
    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
    {
        String className = desc.getName();

        // Deserialize class name: org.joychou.security.AntObjectInputStream$MyObject
        logger.info("Deserialize class name: " + className);

        // Allowlist: only permit known safe types for deserialization
        String[] allowedClasses = {
                "org.joychou.security.AntObjectInputStream$MyObject",
                "org.joychou.dao.User",
                "java.lang.String",
                "java.lang.Number",
                "java.lang.Integer",
                "java.lang.Long",
                "java.lang.Boolean",
                "java.util.ArrayList",
                "java.util.HashMap"
        };

        // Allow primitive types and arrays of allowed types
        if (className.startsWith("[")) {
            // Array type — resolve element type check
            String elementClass = className.replaceAll("^\\[+L?", "").replace(";", "");
            boolean elementAllowed = false;
            for (String allowedClass : allowedClasses) {
                if (elementClass.equals(allowedClass)) {
                    elementAllowed = true;
                    break;
                }
            }
            if (!elementAllowed) {
                throw new InvalidClassException("Unauthorized deserialization attempt", className);
            }
            return super.resolveClass(desc);
        }

        for (String allowedClass : allowedClasses) {
            if (className.equals(allowedClass)) {
                return super.resolveClass(desc);
            }
        }

        throw new InvalidClassException("Unauthorized deserialization attempt", className);
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


