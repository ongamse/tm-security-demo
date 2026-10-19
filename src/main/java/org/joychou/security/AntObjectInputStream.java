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
     * Only allow deserialization of explicitly allowlisted classes.
     *
     * Uses an allowlist approach instead of a bypassable denylist.
     * RASP hooks java/io/ObjectInputStream resolveClass globally;
     * this custom stream enforces the same allowlist principle locally.
     */
    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
    {
        String className = desc.getName();

        // Deserialize class name: org.joychou.security.AntObjectInputStream$MyObject
        logger.info("Deserialize class name: " + className);

        // Allowlist: only permit known safe classes for deserialization
        String[] allowedClasses = {
                "org.joychou.security.AntObjectInputStream$MyObject",
                "org.joychou.dao.User",
                "java.lang.String",
                "java.lang.Number",
                "java.lang.Integer",
                "java.lang.Long"
        };

        boolean allowed = false;
        for (String allowedClass : allowedClasses) {
            if (className.equals(allowedClass)) {
                allowed = true;
                break;
            }
        }

        if (!allowed) {
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


