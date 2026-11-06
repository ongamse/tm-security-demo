package org.joychou.RMI;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMIServerSocketFactory;
import java.rmi.server.UnicastRemoteObject;



public class Server implements Hello {

    public String sayHello() {
        return "Hello Word!";
    }

    public static void main(String args[]) {

        try {
            // JEP 290: allowlist the classes the registry may deserialize, reject everything else.
            System.setProperty("sun.rmi.registry.registryFilter",
                    "java.lang.String;java.lang.Number;java.lang.reflect.Proxy;java.rmi.Remote;"
                            + "java.rmi.server.RemoteObject;java.rmi.server.RemoteObjectInvocationHandler;"
                            + "java.rmi.server.UnicastRef;java.rmi.server.ObjID;java.rmi.server.UID;"
                            + "java.rmi.server.RMIClientSocketFactory;java.rmi.server.RMIServerSocketFactory;"
                            + "sun.rmi.server.UnicastRef;sun.rmi.transport.LiveRef;"
                            + "sun.rmi.transport.tcp.TCPEndpoint;org.joychou.RMI.Hello;!*");
            // Never load classes from a remote codebase, and advertise loopback only.
            System.setProperty("java.rmi.server.useCodebaseOnly", "true");
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            final InetAddress loopback = InetAddress.getLoopbackAddress();
            RMIServerSocketFactory loopbackFactory = new RMIServerSocketFactory() {
                @Override
                public ServerSocket createServerSocket(int port) throws IOException {
                    return new ServerSocket(port, 50, loopback);
                }
            };
            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, loopbackFactory);
            // Registry listens on the loopback interface only.
            Registry registry = LocateRegistry.createRegistry(1099, null, loopbackFactory);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

