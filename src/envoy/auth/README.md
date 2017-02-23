# Istio mTLS on proxies

This proxy implements the Istio mTLS connection. It includes:
- Secure naming
- Client side mTLS connection (Implementing)
- Server side mTLS connection (Implementing)

## How to run

* Start backend Echo server.

```
  cd test/backend/echo
  go run echo.go
```

* Start Envoy proxy, run

```
  src/envoy/auth/start_envoy
```

* Then issue HTTP request to proxy.

```
  curl http://localhost:9090/echo -d "hello world"
```
## Secure Naming

The secure naming map is configured through "auth\_secure\_naming" network
filter. The secure naming map is stored in a singleton, which can be read by the
following filters.
