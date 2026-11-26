/**
 * Self-signed TLS material for LOCAL test servers only (CN=127.0.0.1,
 * SAN IP:127.0.0.1/DNS:localhost, generated with openssl, valid 100 years).
 * Tests disable certificate verification for their worker process; nothing
 * here is ever used outside tests/web.
 */
export const TLS_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5K9GR7TUx7Mi1bDu
oPK5jiDvcGbJtC3HFWM3vxiUta+hRANCAAR4j+HqVis4wMQ/uFr2LlpT2rhjs5c9
voqt34tw7JIjp0BVu16aX1KkoWVDHp8ujvhIYnI2GIiefIhMhvl3/A+H
-----END PRIVATE KEY-----`;

export const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIBaDCCAQ+gAwIBAgIUerpgwW00h/QD+1Z6QKZkJVdD/qAwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MTEyNTE0NTIxN1oYDzIxMjYxMTAx
MTQ1MjE3WjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAR4j+HqVis4wMQ/uFr2LlpT2rhjs5c9voqt34tw7JIjp0BVu16aX1Kk
oWVDHp8ujvhIYnI2GIiefIhMhvl3/A+Hoz0wOzAaBgNVHREEEzARhwR/AAABggls
b2NhbGhvc3QwHQYDVR0OBBYEFMeP5pRsEkZSQLCwCsM4V93uJxYFMAoGCCqGSM49
BAMCA0cAMEQCIHfnr8HxLbvQckW80zybEaSqoQQ7cAKHfUYm447tPLk4AiBVo0e8
XMcXDl02bFyLE3yL/nVtziD27u5zCxe1gsc9mA==
-----END CERTIFICATE-----`;
