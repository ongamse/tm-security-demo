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
            // Restrict what the registry will deserialize (JDK 8u121+): only the types needed to
            // bind/lookup a stub. Respect an operator-supplied filter if one is already set.
            if (System.getProperty("sun.rmi.registry.registryFilter") == null) {
                System.setProperty("sun.rmi.registry.registryFilter",
                        "java.lang.String;java.lang.Number;java.rmi.Remote;java.lang.reflect.Proxy;"
                                + "sun.rmi.server.UnicastRef;sun.rmi.server.UnicastRef2;"
                                + "java.rmi.server.RemoteObjectInvocationHandler;java.rmi.server.RemoteObject;"
                                + "java.rmi.server.RMIClientSocketFactory;java.rmi.server.RMIServerSocketFactory;"
                                + "java.rmi.activation.ActivationID;java.rmi.server.UID;"
                                + "org.joychou.RMI.Hello;!*");
            }
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

