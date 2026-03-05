PROXY

sudo ip tuntap add user monchat mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

-- Then Start


AGENT
./agent -connect 10.10.14.32:11601 -ignore-cert


KALI

sudo ip route add 172.16.1.0/24 dev ligolo
