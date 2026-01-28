# roneai MCP Server Facade

이 폴더는 ONEAI MCP 서버 C 헤더(`oneai_mcp_server.h`)를 러스트로 재구현한 경량 파사드와 예제 데몬을 제공합니다.

## 구조
- `server/` : 라이브러리 크레이트. C 헤더에 대응하는 API를 `rmcp_server.rs`에 구현.
- `examples/` : 데몬 예제 바이너리. 위 라이브러리를 사용하여 서버를 구성하고 실행.
- `scripts/build.sh` : 두 크레이트를 함께 빌드하는 스크립트.

## 빌드
```bash
cd $(git rev-parse --show-toplevel)/roneai
./scripts/build.sh
```

## 실행 (예제 데몬)
```bash
cd $(git rev-parse --show-toplevel)/roneai
cargo run -p roneai-mcp-server-example
```

### 실행 흐름
1. 서버 생성(`oneai_mcp_server_create`) 및 capability 경로 설정.
2. Streamable HTTP 트랜스포트 등록(기본: 127.0.0.1:8080) 및 연결 이벤트 콜백 지정.
3. 도구/리소스/프롬프트 등록.
4. 서버 실행(`oneai_mcp_server_run`) 후 Ctrl+C로 종료.

## 라이선스
모든 소스는 Apache-2.0 라이선스를 따릅니다.
