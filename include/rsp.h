/*
 * rsp.h — GDB Remote Serial Protocol helpers for debugserver communication.
 */

#ifndef RSP_H
#define RSP_H

#include <stddef.h>
#include <stdint.h>

/* Send an RSP packet. Returns 0 on success. */
int rsp_send(int fd, const char *data);

/* Receive an RSP packet. Returns pointer into buf (past the '$'),
 * or NULL on error. Sends '+' ack automatically. */
char *rsp_recv(int fd, char *buf, size_t bufsz);

/* Encode a 64-bit value as 16 hex chars (little-endian byte order). */
void rsp_encode_u64(uint64_t val, char *out);

/* Decode 16 hex chars (little-endian byte order) to a 64-bit value. */
uint64_t rsp_decode_u64(const char *hex);

/* Connect to debugserver on 127.0.0.1:port. Retries up to 3 seconds. */
int rsp_connect(int port);

/* Set a single register via P command. Returns 0 on success. */
int rsp_set_reg(int sock, int regnum, uint64_t val,
                char *buf, size_t bufsz);

#endif /* RSP_H */
