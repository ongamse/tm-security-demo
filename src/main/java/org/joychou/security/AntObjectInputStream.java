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

    // Allowlist of classes that may be deserialized; everything else is rejected.
    private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
            "java.lang.String",
            "java.lang.Number",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Boolean",
            "org.joychou.security.AntObjectInputStream$MyObject"
    ));

    public AntObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    /**
     * 只允许反序列化SerialObject class
     *
     * 在应用上使用黑白名单校验方案比较局限，因为只有使用自己定义的AntObjectInputStream类，进行反序列化才能进行校验。
     * 类似fastjson通用类的反序列化就不能校验。
     * 但是RASP是通过HOOK java/io/ObjectInputStream类的resolveClass方法，全局的检测白名单。
     *
     */
    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException
    {
        String className = desc.getName();

        // Deserialize class name: org.joychou.security.AntObjectInputStream$MyObject
        logger.info("Deserialize class name: " + className);

        // Unwrap array types such as "[Ljava.lang.String;" to the element type name.
        String baseName = className;
        while (baseName.startsWith("[")) {
            baseName = baseName.substring(1);
        }
        if (baseName.startsWith("L") && baseName.endsWith(";")) {
            baseName = baseName.substring(1, baseName.length() - 1);
        }

        // Primitive array element types (e.g. "[B" -> "B") are single characters.
        boolean primitive = baseName.length() == 1 && "BCDFIJSZ".contains(baseName);

        if (!primitive && !ALLOWED_CLASSES.contains(baseName)) {
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


