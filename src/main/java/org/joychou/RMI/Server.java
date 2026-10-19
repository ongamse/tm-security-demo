package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;



public class Server implements Hello {

    // Allowlist of RMI binding names to restrict what can be registered
    private static final Set<String> ALLOWED_BINDINGS = new HashSet<>(Arrays.asList("Hello"));

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Restrict RMI to prevent remote class loading and deserialization attacks
            System.setProperty("java.rmi.server.useCodebaseOnly", "true");

            // Set a deserialization filter to restrict classes (JEP 290, Java 8u121+)
            System.setProperty("sun.rmi.registry.registryFilter",
                    "org.joychou.RMI.*;java.lang.*;java.rmi.**;!*");

            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            LocateRegistry.createRegistry(1099);
            Registry registry = LocateRegistry.getRegistry();

            String bindingName = "Hello";
            if (!ALLOWED_BINDINGS.contains(bindingName)) {
                throw new SecurityException("Binding name not allowed: " + bindingName);
            }
            registry.bind(bindingName, stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

