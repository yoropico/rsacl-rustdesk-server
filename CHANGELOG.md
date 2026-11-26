# 변경이력 (rsacl 포크)

RS 오토메이션이 운영하는 RustDesk ID 서버(hbbs) 포크의 변경이력임. 기준은 공식 rustdesk-server 1.1.16임.

## 2026-11-26 (KST)

- 영역: hbbs ID 서버 접속(TCP 21116)
- 변경: 로그인한 RustDesk 앱(1.5.3)이 원격 연결 시 "Failed to secure tcp: deadline has elapsed"로 끊기던 문제를 고침 -- 서버가 접속 직후 암호화 키 교환을 먼저 제안하고, 앱이 응하면 그 연결을 암호화함
- 영향: 로그인하지 않은 앱과 대리점에 설치된 기존 앱은 키 교환에 응하지 않으므로 지금처럼 암호화 없이 그대로 연결됨
- 패키지 버전: rustdesk-server-hbbs 1.1.16+rsacl1
