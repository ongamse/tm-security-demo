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
            // Restrict what the registry may deserialize (JEP 290) so a crafted bind/rebind
            // payload cannot trigger gadget chains. Must be set before the registry is created.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.Remote;"
                            + "java.rmi.server.**;java.rmi.activation.ActivationID;"
                            + "sun.rmi.server.**;sun.rmi.transport.**;!*");
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);
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

