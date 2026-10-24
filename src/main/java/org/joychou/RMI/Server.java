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

    /**
     * RMIServerSocketFactory that binds only to the loopback address,
     * preventing remote connections and mitigating RMI deserialization attacks.
     */
    private static class LocalhostServerSocketFactory implements RMIServerSocketFactory {
        @Override
        public ServerSocket createServerSocket(int port) throws IOException {
            return new ServerSocket(port, 0, InetAddress.getLoopbackAddress());
        }
    }

    public static void main(String args[]) {

        try {
            // Restrict RMI to localhost to prevent remote deserialization attacks (CWE-77)
            System.setProperty("java.rmi.server.hostname", "127.0.0.1");
            RMIServerSocketFactory ssf = new LocalhostServerSocketFactory();

            Server obj = new Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0, null, ssf);
            Registry registry = LocateRegistry.createRegistry(1099, null, ssf);
            registry.bind("Hello", stub);
            System.out.println("绑定1099端口成功");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }
}

