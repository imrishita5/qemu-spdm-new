#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/i2c.h"

#define SPDM_I2C_TEST_ID    "spdm-i2c-test"
#define SPDM_I2C_TEST_ADDR  0x55
#define MCTP_CMD_CODE       0x0F
#define MCTP_HDR_VERSION    0x01
#define MCTP_SMBUS_MTU      68
#define SPDM_I2C_EID        0x08
#define SPDM_I2C_SRC_ADDR   ((SPDM_I2C_TEST_ADDR << 1) | 1)
#define MCTP_FLAG_SOM  0x80
#define MCTP_FLAG_EOM  0x40
#define SPDM_CERT_PATH \
    "/home/rishita.makde/libspdm/unit_test/sample_key/ecp256/" \
    "bundle_responder.certchain.der"
#define SPDM_KEY_PATH \
    "/home/rishita.makde/libspdm/unit_test/sample_key/ecp256/" \
    "end_responder.key"

/* Helper: build one MCTP packet frame */
static int build_mctp_frame(uint8_t *buf, uint8_t flags,
                            const uint8_t *payload, int plen)
{
    int i = 0;
    buf[i++] = MCTP_CMD_CODE;
    buf[i++] = 1 + 4 + plen;   /* byte_count */
    buf[i++] = 0x23;            /* fake src slave addr */
    buf[i++] = MCTP_HDR_VERSION;
    buf[i++] = SPDM_I2C_EID;   /* dest EID = our device */
    buf[i++] = 0x07;            /* src EID = requester */
    buf[i++] = flags;
    memcpy(buf + i, payload, plen);
    return i + plen;
}

/* Single-packet request, single-packet response */
static void test_mctp_roundtrip(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t payload[] = { 0x01 };
    uint8_t frame[16];
    /* flags: SOM|EOM|TO, seq=0, tag=0 → 0xC8 */
    int flen = build_mctp_frame(frame, 0xC8, payload, sizeof(payload));

    qi2c_send(i2cdev, frame, flen);

    uint8_t resp[6];
    qi2c_recv(i2cdev, resp, sizeof(resp));

    /* resp[0]=byte_count, resp[1]=src_addr, resp[2]=MCTP_ver */
    g_assert_cmphex(resp[0], ==, 1 + 4 + 1);   /* byte_count for 1-byte payload */
    g_assert_cmphex(resp[1], ==, SPDM_I2C_SRC_ADDR);
    g_assert_cmphex(resp[2], ==, MCTP_HDR_VERSION);
}

/* Two-packet request reassembled into one message, one-packet response */
static void test_multipacket_request(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t p1[4] = { 0x01, 0x02, 0x03, 0x04 };
    uint8_t p2[4] = { 0x05, 0x06, 0x07, 0x08 };
    uint8_t frame[32];
    int flen;

    /* Packet 1: SOM, no EOM, seq=0 → flags=0x88 (SOM|TO) */
    flen = build_mctp_frame(frame, 0x88, p1, sizeof(p1));
    qi2c_send(i2cdev, frame, flen);

    /* Packet 2: no SOM, EOM, seq=1 → flags=0x50 (EOM|seq=1) */
    flen = build_mctp_frame(frame, 0x50, p2, sizeof(p2));
    qi2c_send(i2cdev, frame, flen);

    /* Read response — reassembly triggered handle_message → echo path. */
    uint8_t resp[8];
    qi2c_recv(i2cdev, resp, sizeof(resp));

    g_assert_cmphex(resp[1], ==, SPDM_I2C_SRC_ADDR);
    g_assert_cmphex(resp[2], ==, MCTP_HDR_VERSION);
    /* SOM+EOM set (single response packet) */
    g_assert_cmphex(resp[5] & 0xC0, ==, 0xC0);
    /* Echo payload starts with first reassembled byte (0x01). */
    g_assert_cmphex(resp[6], ==, 0x01);
}

/* Single request with 0xFF payload triggers 100-byte stub → 2 response packets */
static void test_fragmented_response(void *obj, void *data,
                                     QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t payload[] = { 0xFF };  /* triggers 100-byte stub response */
    uint8_t frame[16];
    int flen = build_mctp_frame(frame, 0xC8, payload, sizeof(payload));
    qi2c_send(i2cdev, frame, flen);

    /* Packet 1: should be SOM, no EOM, 68-byte payload */
    uint8_t r1[80];
    qi2c_recv(i2cdev, r1, MCTP_SMBUS_MTU + 6);
    g_assert_cmphex(r1[0], ==, 1 + 4 + MCTP_SMBUS_MTU);  /* byte_count */
    g_assert_cmphex(r1[5] & MCTP_FLAG_SOM, ==, MCTP_FLAG_SOM);  /* SOM set */
    g_assert_cmphex(r1[5] & MCTP_FLAG_EOM, ==, 0);              /* EOM clear */

    /* Packet 2: no SOM, EOM, 32-byte payload (100 - 68) */
    uint8_t r2[48];
    qi2c_recv(i2cdev, r2, 32 + 6);
    g_assert_cmphex(r2[5] & MCTP_FLAG_SOM, ==, 0);              /* SOM clear */
    g_assert_cmphex(r2[5] & MCTP_FLAG_EOM, ==, MCTP_FLAG_EOM);  /* EOM set */
    /* seq=1 in bits 5:4 */
    g_assert_cmphex((r2[5] >> 4) & 0x3, ==, 1);
}

/* Sequence mismatch: mid-message wrong seq → device resets, recovers on next SOM */
static void test_seq_mismatch(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t p1[] = { 0x01 };
    uint8_t p_bad[] = { 0x02 };
    uint8_t p_recovery[] = { 0x03 };
    uint8_t frame[16];
    int flen;

    /* Start a message (SOM, seq=0) */
    flen = build_mctp_frame(frame, 0x88, p1, sizeof(p1));
    qi2c_send(i2cdev, frame, flen);

    /* Send wrong seq (seq=3 instead of expected 1) → mismatch */
    flen = build_mctp_frame(frame, 0x70, p_bad, sizeof(p_bad));
    qi2c_send(i2cdev, frame, flen);

    /* Device should have no pending response */
    uint8_t resp[4];
    qi2c_recv(i2cdev, resp, sizeof(resp));
    /* No valid response built — tx_len=0 — device returns 0xFF */
    g_assert_cmphex(resp[0], ==, 0xFF);

    /* Recovery: send fresh SOM+EOM → device processes normally */
    flen = build_mctp_frame(frame, 0xC8, p_recovery, sizeof(p_recovery));
    qi2c_send(i2cdev, frame, flen);

    uint8_t resp2[8];
    qi2c_recv(i2cdev, resp2, sizeof(resp2));
    g_assert_cmphex(resp2[1], ==, SPDM_I2C_SRC_ADDR);  /* valid response */
}

/* Truncated frame: fewer bytes than byte_count → device discards silently */
static void test_truncated_frame(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;

    /* Build a frame claiming 10 payload bytes but only send 3 */
    uint8_t frame[] = {
        MCTP_CMD_CODE,
        1 + 4 + 10,     /* byte_count claims 10 payload bytes */
        0x23,           /* src addr */
        MCTP_HDR_VERSION,
        SPDM_I2C_EID,
        0x07,
        0xC8,           /* SOM|EOM */
        0x01, 0x02, 0x03  /* only 3 bytes instead of 10 */
    };
    qi2c_send(i2cdev, frame, sizeof(frame));

    /* No valid response should be built */
    uint8_t resp[4];
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[0], ==, 0xFF);

    /* Device recovers: next valid frame works */
    uint8_t p[] = { 0x01 };
    uint8_t good_frame[16];
    int flen = build_mctp_frame(good_frame, 0xC8, p, sizeof(p));
    qi2c_send(i2cdev, good_frame, flen);

    uint8_t resp2[8];
    qi2c_recv(i2cdev, resp2, sizeof(resp2));
    g_assert_cmphex(resp2[1], ==, SPDM_I2C_SRC_ADDR);
}

/* Oversized frame: byte_count > MTU → device rejects */
static void test_oversized_frame(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;

    uint8_t frame[16] = {
        MCTP_CMD_CODE,
        0xFF,           /* byte_count=255, way over MTU */
        0x23,
        MCTP_HDR_VERSION,
        SPDM_I2C_EID,
        0x07,
        0xC8,
        0x01
    };
    qi2c_send(i2cdev, frame, 8);

    uint8_t resp[4];
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[0], ==, 0xFF);  /* no valid response */
}

/* byte_count=3: too small to hold src_addr(1)+mctp_hdr(4) */
static void test_underflow_frame(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[] = { MCTP_CMD_CODE, 0x03, 0x23, 0x01, 0x08 };
    qi2c_send(i2cdev, frame, sizeof(frame));

    uint8_t resp[4];
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[0], ==, 0xFF);
}

static void test_spdm_get_version(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    /* SPDM GET_VERSION: msg_type=0x05, SPDMVersion=0x10, code=0x84, p1=p2=0 */
    uint8_t spdm_req[] = { 0x05, 0x10, 0x84, 0x00, 0x00 };
    uint8_t frame[32];
    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                spdm_req, sizeof(spdm_req));
    qi2c_send(i2cdev, frame, flen);

    uint8_t resp[32];
    qi2c_recv(i2cdev, resp, sizeof(resp));

    /* resp layout: [0]=byte_count [1]=src_addr [2]=MCTP_ver [3]=dst_eid
     *              [4]=src_eid [5]=flags [6]=SPDM_type [7]=SPDM_ver [8]=code */
    g_assert_cmphex(resp[6], ==, 0x05); /* SPDM message type over MCTP */
    g_assert_cmphex(resp[8], ==, 0x04); /* VERSION response code */
}

static void test_spdm_get_capabilities(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t get_version[] = { 0x05, 0x10, 0x84, 0x00, 0x00 };
    uint8_t get_caps[] = {
        0x05, 0x11, 0xE1, 0x00, 0x00,
        0x00, 0x0B, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00
    };
    uint8_t frame[64];
    uint8_t resp[64];
    int flen;

    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            get_version, sizeof(get_version));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[8], ==, 0x04);

    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            get_caps, sizeof(get_caps));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));

    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x61);
    g_assert_cmphex(resp[15], ==, 0x3e);
}

static void test_spdm_negotiation_bad_length(void *obj, void *data,
                                             QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t bad_neg_alg[] = {
        0x05, 0x11, 0xE3, 0x00, 0x00,
        0x20, 0x00,
        0x01, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    uint8_t frame[64];
    uint8_t resp[16];
    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                bad_neg_alg, sizeof(bad_neg_alg));

    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));

    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x7f);
}

static void test_spdm_negotiation(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8];
    uint8_t resp[64];
    int flen;

    uint8_t get_version[] = { 0x05, 0x10, 0x84, 0x00, 0x00 };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            get_version, sizeof(get_version));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, 32);
    g_assert_cmphex(resp[8], ==, 0x04);

    uint8_t get_caps[] = {
        0x05, 0x11, 0xE1, 0x00, 0x00,
        0x00, 0x0B, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00
    };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            get_caps, sizeof(get_caps));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, 32);
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x61);

    uint8_t neg_alg[] = {
        0x05, 0x11, 0xE3, 0x00, 0x00,
        0x20, 0x00,
        0x01, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            neg_alg, sizeof(neg_alg));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, 64);
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x63);
}

static void spdm_negotiate(QI2CDevice *dev)
{
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[64];
    int flen;

    uint8_t gv[] = { 0x05, 0x10, 0x84, 0x00, 0x00 };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08, gv, sizeof(gv));
    qi2c_send(dev, frame, flen); qi2c_recv(dev, resp, 32);
    g_assert_cmphex(resp[8], ==, 0x04);

    uint8_t gc[] = { 0x05, 0x11, 0xE1, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00,
                     0x06, 0x00, 0x00, 0x00 };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08, gc, sizeof(gc));
    qi2c_send(dev, frame, flen); qi2c_recv(dev, resp, 32);
    g_assert_cmphex(resp[8], ==, 0x61);

    uint8_t na[] = { 0x05, 0x11, 0xE3, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00,
                     0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                     0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                     0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00 };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08, na, sizeof(na));
    qi2c_send(dev, frame, flen); qi2c_recv(dev, resp, 64);
    g_assert_cmphex(resp[8], ==, 0x63);
}

static void test_spdm_get_digests(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[64];
    spdm_negotiate(i2cdev);
    uint8_t gd[] = { 0x05, 0x11, 0x81, 0x00, 0x00 };
    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08, gd, sizeof(gd));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, 64);
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x01); /* DIGESTS */
}

static void test_spdm_get_certificate(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[80];
    spdm_negotiate(i2cdev);
    /* Request 58 bytes — fits in one MCTP packet */
    uint8_t gcert[] = { 0x05, 0x11, 0x82, 0x00, 0x00,
                        0x00, 0x00,   /* Offset=0 */
                        0x3A, 0x00 }; /* Length=58 */
    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                gcert, sizeof(gcert));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, 80);
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x02); /* CERTIFICATE */
}

/*
 * CHALLENGE → CHALLENGE_AUTH (135-byte response = 2 MCTP packets: 68 + 67).
 * Verifies: SPDM type (0x05) and CHALLENGE_AUTH code (0x03) in packet 1;
 * EOM + seq=1 in packet 2.
 */
static void test_spdm_challenge(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8];
    uint8_t r1[6 + MCTP_SMBUS_MTU];
    uint8_t r2[6 + (135 - MCTP_SMBUS_MTU)];

    spdm_negotiate(i2cdev);

    /* CHALLENGE: MCTP type + SPDM header (4B) + nonce (32B) = 37 bytes */
    uint8_t challenge[37];
    challenge[0] = 0x05;       /* MCTP SPDM message type */
    challenge[1] = 0x11;       /* SPDM version 1.1 */
    challenge[2] = 0x83;       /* CHALLENGE request code */
    challenge[3] = 0x00;       /* slot 0 */
    challenge[4] = 0x00;       /* no measurement hash */
    memset(challenge + 5, 0xAA, 32);  /* nonce */

    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                challenge, sizeof(challenge));
    qi2c_send(i2cdev, frame, flen);

    /* Packet 1: SOM, 68-byte payload carrying SPDM header */
    qi2c_recv(i2cdev, r1, sizeof(r1));
    g_assert_cmphex(r1[5] & MCTP_FLAG_SOM, ==, MCTP_FLAG_SOM);
    g_assert_cmphex(r1[5] & MCTP_FLAG_EOM, ==, 0);
    g_assert_cmphex(r1[6], ==, 0x05);  /* SPDM over MCTP */
    g_assert_cmphex(r1[8], ==, 0x03);  /* CHALLENGE_AUTH */

    /* Packet 2: EOM, seq=1, 67-byte signature tail */
    qi2c_recv(i2cdev, r2, sizeof(r2));
    g_assert_cmphex(r2[5] & MCTP_FLAG_EOM, ==, MCTP_FLAG_EOM);
    g_assert_cmphex((r2[5] >> 4) & 0x3, ==, 1);  /* seq=1 */
}

/* GET_MEASUREMENTS: no signature, query total count — single-packet response */
static void test_spdm_get_measurements_count(void *obj, void *data,
                                              QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[32];

    spdm_negotiate(i2cdev);

    uint8_t req[] = { 0x05, 0x11, 0xE0, 0x00, 0xFE };
    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                req, sizeof(req));
    qi2c_send(i2cdev, frame, flen);

    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[6], ==, 0x05);  /* SPDM over MCTP */
    g_assert_cmphex(resp[8], ==, 0x60);  /* MEASUREMENTS */
}

/*
 * GET_MEASUREMENTS: index 1, GENERATE_SIGNATURE.
 * Response = MCTP_type(1)+SPDM_hdr(4)+nblocks(1)+rec_len(3)
 *            +block_hdr(7)+SHA256(32)+nonce(32)+opaque_len(2)+sig(64)
 *          = 146 bytes → 3 MCTP packets: 68 + 68 + 10.
 */
static void test_spdm_get_measurements_signed(void *obj, void *data,
                                               QGuestAllocator *alloc)
{
#define SPDM_MEAS1_PAYLOAD      146
#define SPDM_MEAS1_P3_PAYLOAD   (SPDM_MEAS1_PAYLOAD - 2 * MCTP_SMBUS_MTU)

    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8];
    uint8_t r1[6 + MCTP_SMBUS_MTU];
    uint8_t r2[6 + MCTP_SMBUS_MTU];
    uint8_t r3[6 + SPDM_MEAS1_P3_PAYLOAD];

    spdm_negotiate(i2cdev);

    /* GET_MEASUREMENTS: Param1=GENERATE_SIGNATURE, Param2=index 1, nonce, slot 0 */
    uint8_t req[38];
    req[0] = 0x05;             /* MCTP SPDM type */
    req[1] = 0x11;             /* SPDM version */
    req[2] = 0xE0;             /* GET_MEASUREMENTS */
    req[3] = 0x01;             /* Param1: GENERATE_SIGNATURE */
    req[4] = 0x01;             /* Param2: index 1 */
    memset(req + 5, 0xBB, 32); /* nonce */
    req[37] = 0x00;            /* SlotIDParam */

    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                req, sizeof(req));
    qi2c_send(i2cdev, frame, flen);

    /* Packet 1: SOM, SPDM header visible */
    qi2c_recv(i2cdev, r1, sizeof(r1));
    g_assert_cmphex(r1[5] & MCTP_FLAG_SOM, ==, MCTP_FLAG_SOM);
    g_assert_cmphex(r1[5] & MCTP_FLAG_EOM, ==, 0);
    g_assert_cmphex(r1[6], ==, 0x05);   /* SPDM type */
    g_assert_cmphex(r1[8], ==, 0x60);   /* MEASUREMENTS */
    g_assert_cmphex(r1[11], ==, 1);     /* NumberOfBlocks */

    /* Packet 2: seq=1, middle */
    qi2c_recv(i2cdev, r2, sizeof(r2));
    g_assert_cmphex(r2[5] & MCTP_FLAG_SOM, ==, 0);
    g_assert_cmphex(r2[5] & MCTP_FLAG_EOM, ==, 0);
    g_assert_cmphex((r2[5] >> 4) & 0x3, ==, 1);

    /* Packet 3: seq=2, EOM, signature tail */
    qi2c_recv(i2cdev, r3, sizeof(r3));
    g_assert_cmphex(r3[5] & MCTP_FLAG_EOM, ==, MCTP_FLAG_EOM);
    g_assert_cmphex((r3[5] >> 4) & 0x3, ==, 2);
}

/* Unsupported SPDM request code should always return SPDM_ERROR. */
static void test_spdm_error_unexpected_request(void *obj, void *data,
                                                QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[32];

    uint8_t req[] = { 0x05, 0x11, 0xDE, 0x00, 0x00 };

    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                req, sizeof(req));
    qi2c_send(i2cdev, frame, flen);

    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x7F);
}

/* After GET_VERSION, send CAPABILITIES with bogus version → ERROR(UnexpectedRequest) */
static void test_spdm_error_version_mismatch(void *obj, void *data,
                                              QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[32];
    int flen;

    uint8_t gv[] = { 0x05, 0x10, 0x84, 0x00, 0x00 };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            gv, sizeof(gv));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[8], ==, 0x04);

    uint8_t bad_caps[] = {
        0x05, 0xEE,                     /* bogus SPDM version */
        0xE1, 0x00, 0x00,
        0x00, 0x0B, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00
    };
    flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                            bad_caps, sizeof(bad_caps));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x7F);
    g_assert_cmphex(resp[9], ==, 0x41); /* UnexpectedRequest */
}

/* CHALLENGE to slot 7 (slot_mask=0x01, only slot 0 provisioned) → ERROR */
static void test_spdm_challenge_bad_slot(void *obj, void *data,
                                          QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[32];

    spdm_negotiate(i2cdev);

    uint8_t challenge[37];
    challenge[0] = 0x05; challenge[1] = 0x11; challenge[2] = 0x83;
    challenge[3] = 0x07;           /* slot 7, not provisioned */
    challenge[4] = 0x00;
    memset(challenge + 5, 0xCC, 32);

    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                challenge, sizeof(challenge));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x7F);
    g_assert_cmphex(resp[9], ==, 0x01); /* InvalidRequest */
}

/* GET_MEASUREMENTS with index 0x50 (not registered in meas.c) → ERROR */
static void test_spdm_measurements_invalid_index(void *obj, void *data,
                                                   QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = obj;
    uint8_t frame[MCTP_SMBUS_MTU + 8], resp[32];

    spdm_negotiate(i2cdev);

    uint8_t req[38];
    req[0] = 0x05; req[1] = 0x11; req[2] = 0xE0;
    req[3] = 0x01;   /* GENERATE_SIGNATURE */
    req[4] = 0x50;   /* invalid index */
    memset(req + 5, 0xDD, 32);
    req[37] = 0x00;

    int flen = build_mctp_frame(frame, MCTP_FLAG_SOM | MCTP_FLAG_EOM | 0x08,
                                req, sizeof(req));
    qi2c_send(i2cdev, frame, flen);
    qi2c_recv(i2cdev, resp, sizeof(resp));
    g_assert_cmphex(resp[6], ==, 0x05);
    g_assert_cmphex(resp[8], ==, 0x7F);
    g_assert_cmphex(resp[9], ==, 0x01); /* InvalidRequest */
}

static void spdm_i2c_register_nodes(void)
{
    QOSGraphEdgeOptions opts = {
        .extra_device_opts = "id=" SPDM_I2C_TEST_ID ",address=0x55"
                     ",cert-chain=" SPDM_CERT_PATH
                     ",cert-key=" SPDM_KEY_PATH
    };
    add_qi2c_address(&opts, &(QI2CAddress) { SPDM_I2C_TEST_ADDR });

    qos_node_create_driver("spdm-i2c", i2c_device_create);
    qos_node_consumes("spdm-i2c", "i2c-bus", &opts);

    qos_add_test("mctp-roundtrip",       "spdm-i2c", test_mctp_roundtrip,       NULL);
    qos_add_test("multipacket-request",  "spdm-i2c", test_multipacket_request,  NULL);
    qos_add_test("fragmented-response",  "spdm-i2c", test_fragmented_response,  NULL);
    qos_add_test("seq-mismatch",         "spdm-i2c", test_seq_mismatch,         NULL);
    qos_add_test("truncated-frame",      "spdm-i2c", test_truncated_frame,      NULL);
    qos_add_test("oversized-frame",      "spdm-i2c", test_oversized_frame,      NULL);
    qos_add_test("underflow-frame", "spdm-i2c", test_underflow_frame, NULL);
    qos_add_test("spdm-get-version", "spdm-i2c", test_spdm_get_version, NULL);
    qos_add_test("spdm-get-capabilities", "spdm-i2c", test_spdm_get_capabilities, NULL);
    qos_add_test("spdm-negotiation-bad-length", "spdm-i2c", test_spdm_negotiation_bad_length, NULL);
    qos_add_test("spdm-negotiation", "spdm-i2c", test_spdm_negotiation, NULL);
    qos_add_test("spdm-get-digests",      "spdm-i2c", test_spdm_get_digests,      NULL);
    qos_add_test("spdm-get-certificate",  "spdm-i2c", test_spdm_get_certificate,  NULL);
    qos_add_test("spdm-challenge",        "spdm-i2c", test_spdm_challenge,        NULL);
    qos_add_test("spdm-get-measurements-count",  "spdm-i2c",
                 test_spdm_get_measurements_count,  NULL);
    qos_add_test("spdm-get-measurements-signed", "spdm-i2c",
                 test_spdm_get_measurements_signed, NULL);
    qos_add_test("spdm-error-unexpected-request",   "spdm-i2c",
                 test_spdm_error_unexpected_request,   NULL);
    qos_add_test("spdm-error-version-mismatch",     "spdm-i2c",
                 test_spdm_error_version_mismatch,     NULL);
    qos_add_test("spdm-challenge-bad-slot",         "spdm-i2c",
                 test_spdm_challenge_bad_slot,         NULL);
    qos_add_test("spdm-measurements-invalid-index", "spdm-i2c",
                 test_spdm_measurements_invalid_index, NULL);
}

libqos_init(spdm_i2c_register_nodes);