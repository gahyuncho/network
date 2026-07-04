# PCAP TCP/HTTP Sniffer

White Hat School 4기 - 네트워크 보안 과제

C/libpcap 기반 TCP 패킷 스니퍼. Ethernet/IP/TCP 헤더와 HTTP Message를 파싱하여 출력한다.

## 빌드 및 실행
​```bash
gcc -o sniff_tcp_http sniff_tcp_http.c -lpcap
sudo ./sniff_tcp_http [interface]
​```

## 주요 로직
- `ip->iph_ihl * 4` 로 IP Header 실제 길이 계산
- `TH_OFF(tcp) * 4` 로 TCP Header 실제 길이 계산 (옵션 필드 대응)
- `ntohs(ip->iph_len)` 기반으로 HTTP Payload 위치/길이 역산
