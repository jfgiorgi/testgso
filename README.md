# testgso

poc/test for https://github.com/quic-go/quic-go/issues/3911

ok machine:

    remote v4 = 127.0.0.1:0
    remote v6 = ::1:0
    Kernel detection:
      IPv4 GSO: true
      IPv6 GSO: true
    IPv4 with GSO:
      Write:  n,nb,err = 4000,24,nil
      Write with batch:  n,nb,err = 4000,24,nil
    IPv4 without GSO:
      Write:  n,nb,err = 4000,0,nil
      Write with batch:  n,nb,err = 4000,0,nil
    IPv6 with GSO:
      Write:  n,nb,err = 4000,24,nil
      Write with batch:  n,nb,err = 4000,24,nil
    IPv6 without GSO:
      Write:  n,nb,err = 4000,0,nil
      Write with batch:  n,nb,err = 4000,0,nil

ko machine:

      remote v4 = 127.0.0.1:0
      remote v6 = ::1:0
      Kernel detection:
        IPv4 GSO: true
        IPv6 GSO: true
      IPv4 with GSO:
        Write:  n,nb,err = 4000,24,nil
        Write with batch:  n,nb,err = 4000,24,nil
      IPv4 without GSO:
        Write:  n,nb,err = 4000,0,nil
        Write with batch:  n,nb,err = 4000,0,nil
      IPv6 with GSO:
        Write:  n,nb,err = 0,0,write udp6 [::]:55065->[::1]:55065: sendmsg: invalid argument
        Write with batch:unexpected number of msg sent
        n,nb,err = 0,0,write udp [::]:55065: sendmmsg: invalid argument
      IPv6 without GSO:
        Write:  n,nb,err = 4000,0,nil
        Write with batch:  n,nb,err = 4000,0,nil
