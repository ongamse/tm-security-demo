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
            // Restrict RMI registry deserialization to prevent arbitrary class instantiation
            // Strict deserialization filter: only allow safe base types, RMI framework, and project RMI interface
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.Integer;java.lang.Long;"
                    + "java.lang.Boolean;java.lang.Byte;java.lang.Short;java.lang.Float;"
                    + "java.lang.Double;java.lang.Character;java.io.Serializable;"
                    + "java.rmi.**;javax.rmi.**;org.joychou.RMI.*;!*");
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

