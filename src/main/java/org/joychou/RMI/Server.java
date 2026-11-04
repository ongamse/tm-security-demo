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
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
            // Restrict what the registry may deserialize (JDK 8u121+ honours this property),
            // so a malicious bind/rebind payload cannot trigger gadget-chain code execution.
            if (System.getProperty("sun.rmi.registry.registryFilter") == null) {
                System.setProperty("sun.rmi.registry.registryFilter",
                        "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                                + "java.rmi.server.*;java.rmi.activation.ActivationID;"
                                + "sun.rmi.server.*;sun.rmi.transport.tcp.*;"
                                + "org.joychou.RMI.Hello;!*");
            }
            LocateRegistry.createRegistry(1099);
            Registry registry = LocateRegistry.getRegistry();
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

