package org.joychou.RMI;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // Restrict deserialization on the registry to the types needed by RMI itself (JEP 290).
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                            + "java.rmi.server.**;sun.rmi.server.**;!*");
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            Registry registry = LocateRegistry.createRegistry(1099);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

