#include "qemu/osdep.h"
#include "hw/i2c/i2c.h"
#include "hw/core/qdev-properties.h"
#include "qemu/log.h"
#include "qom/object.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);
bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size);
void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size);

/* Present only when libspdm is built with non-raw-only private-key mode. */
extern bool g_private_key_mode __attribute__((weak));

#define TYPE_SPDM_I2C "spdm-i2c"
OBJECT_DECLARE_SIMPLE_TYPE(SpdmI2cState, SPDM_I2C)

#define MCTP_CMD_CODE        0x0F
#define MCTP_HDR_VERSION     0x01
#define MCTP_SMBUS_MTU       68      /* max payload bytes per packet, DSP0237 */
#define MCTP_MAX_MSG         4096    /* max reassembled message size */
#define SPDM_I2C_EID         0x08

/* Flags byte fields */
#define MCTP_FLAG_SOM        (1 << 7)
#define MCTP_FLAG_EOM        (1 << 6)
#define MCTP_SEQ(flags)      (((flags) >> 4) & 0x3)
#define MCTP_TAG(flags)      ((flags) & 0x7)

/* Max valid byte_count = src_addr(1) + mctp_hdr(4) + MTU payload */
#define MCTP_MAX_BCNT        (1 + 4 + MCTP_SMBUS_MTU)
#define SPDM_BUF_SIZE MCTP_MAX_MSG

typedef enum {
    RX_WAIT_CMD,
    RX_WAIT_BCNT,
    RX_WAIT_SRC,
    RX_MCTP_HDR,
    RX_PAYLOAD,
} RxState;

typedef struct SpdmI2cState {
    I2CSlave parent_obj;

    /* Per-packet RX parse */
    RxState  rx_state;
    uint8_t  rx_byte_count;
    uint8_t  rx_src_addr;
    uint8_t  rx_mctp_hdr[4];
    int      rx_mctp_hdr_pos;
    uint8_t  rx_payload[MCTP_SMBUS_MTU];
    int      rx_payload_len;
    int      rx_payload_total;
    bool     rx_oversized;       /* byte_count exceeded MTU */

    /* Reassembly across packets */
    uint8_t  msg_buf[MCTP_MAX_MSG];
    int      msg_len;
    uint8_t  expected_seq;
    uint8_t  current_tag;
    uint8_t  peer_eid;
    bool     assembling;
    bool     seq_error;

    /* Fragmentation of outgoing response */
    uint8_t  resp_buf[MCTP_MAX_MSG];
    int      resp_total;
    int      resp_offset;
    uint8_t  resp_next_seq;
    uint8_t  resp_dst_eid;
    uint8_t  resp_src_eid;
    uint8_t  resp_tag;
    bool     resp_pending;

    /* Current outgoing packet */
    uint8_t  tx_buf[MCTP_SMBUS_MTU + 8];
    int      tx_pos;
    int      tx_len;

    bool     pec_enabled;  /* Phase 6: CRC-8 PEC */
    char    *cert_chain_path;
    char    *cert_key_path;         /* Phase 8: private key for CHALLENGE */
    
    void    *spdm_ctx;
    void    *spdm_scratch;
    bool     spdm_ready;
    uint8_t  spdm_response[MCTP_MAX_MSG];
    size_t   spdm_response_len;
    uint8_t *cert_chain_data;
    size_t   cert_chain_size;
} SpdmI2cState;

static const Property spdm_i2c_props[] = {
    DEFINE_PROP_STRING("cert-chain", SpdmI2cState, cert_chain_path),
    DEFINE_PROP_STRING("cert-key",   SpdmI2cState, cert_key_path),
};

static void spdm_i2c_build_next_packet(SpdmI2cState *dev);
static void spdm_i2c_realize(DeviceState *dev, Error **errp);

static void spdm_i2c_queue_response(SpdmI2cState *s, const uint8_t *data, int len)
{
    memcpy(s->resp_buf, data, len);
    s->resp_total = len;
    s->resp_offset = 0;
    s->resp_next_seq = 0;
    s->resp_dst_eid = s->peer_eid;
    s->resp_src_eid = SPDM_I2C_EID;
    s->resp_tag = s->current_tag;
    s->resp_pending = true;
}

static bool spdm_i2c_build_get_digests_response(SpdmI2cState *s, uint8_t version)
{
    uint8_t digest[32];
    gsize digest_len = sizeof(digest);
    GChecksum *checksum;
    uint8_t rsp[1 + 4 + sizeof(digest)];

    if (s->cert_chain_data == NULL || s->cert_chain_size == 0) {
        return false;
    }

    checksum = g_checksum_new(G_CHECKSUM_SHA256);
    if (checksum == NULL) {
        return false;
    }

    g_checksum_update(checksum, s->cert_chain_data, s->cert_chain_size);
    g_checksum_get_digest(checksum, digest, &digest_len);
    g_checksum_free(checksum);
    if (digest_len != sizeof(digest)) {
        return false;
    }

    rsp[0] = 0x05;
    rsp[1] = version;
    rsp[2] = 0x01; /* SPDM_DIGESTS */
    rsp[3] = 0x00;
    rsp[4] = 0x01; /* slot 0 populated */
    memcpy(rsp + 5, digest, sizeof(digest));

    spdm_i2c_queue_response(s, rsp, sizeof(rsp));
    return true;
}

static bool spdm_i2c_build_get_certificate_response(SpdmI2cState *s)
{
    uint16_t offset;
    uint16_t req_len;
    uint16_t portion_len;
    uint16_t remainder_len;
    uint8_t *rsp;
    int rsp_len;

    if (s->msg_len < 9 || s->cert_chain_data == NULL || s->cert_chain_size == 0) {
        return false;
    }

    offset = (uint16_t)(s->msg_buf[5] | (s->msg_buf[6] << 8));
    req_len = (uint16_t)(s->msg_buf[7] | (s->msg_buf[8] << 8));

    if (offset >= s->cert_chain_size) {
        return false;
    }

    portion_len = MIN(req_len, (uint16_t)(s->cert_chain_size - offset));
    remainder_len = (uint16_t)(s->cert_chain_size - offset - portion_len);

    rsp_len = 9 + portion_len;
    rsp = g_malloc(rsp_len);

    rsp[0] = 0x05;
    rsp[1] = s->msg_buf[1];
    rsp[2] = 0x02; /* SPDM_CERTIFICATE */
    rsp[3] = s->msg_buf[3];
    rsp[4] = 0x00;
    rsp[5] = (uint8_t)(portion_len & 0xFF);
    rsp[6] = (uint8_t)(portion_len >> 8);
    rsp[7] = (uint8_t)(remainder_len & 0xFF);
    rsp[8] = (uint8_t)(remainder_len >> 8);
    memcpy(rsp + 9, s->cert_chain_data + offset, portion_len);

    spdm_i2c_queue_response(s, rsp, rsp_len);
    g_free(rsp);
    return true;
}

/*
 * Handle a fully reassembled MCTP message.
 * Phase 5: replace stub with libspdm_process_request().
 * Trigger: payload[0] == 0xFF → return 100-byte stub (fragmentation test).
 */
static void spdm_i2c_handle_message(SpdmI2cState *s)
{
    if (s->msg_len < 1) {
        return;
    }

    /* SPDM message type byte 0x05 → dispatch through libspdm */
    if (s->msg_len >= 1 && s->msg_buf[0] == 0x05 && s->spdm_ready) {
        if (s->msg_len >= 5 && s->msg_buf[2] == 0x81 &&
            spdm_i2c_build_get_digests_response(s, s->msg_buf[1])) {
            return;
        }

        if (s->msg_len >= 9 && s->msg_buf[2] == 0x82 &&
            spdm_i2c_build_get_certificate_response(s)) {
            return;
        }

        libspdm_return_t status;
        s->spdm_response_len = 0;

        status = libspdm_responder_dispatch_message(s->spdm_ctx);
            
        if (LIBSPDM_STATUS_IS_ERROR(status) || s->spdm_response_len == 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "spdm-i2c: libspdm dispatch error 0x%x\n", status);
            return;
        }

        memcpy(s->resp_buf, s->spdm_response, s->spdm_response_len);
        s->resp_total  = (int)s->spdm_response_len;
        s->resp_offset = 0;
        s->resp_next_seq = 0;
        s->resp_dst_eid  = s->peer_eid;
        s->resp_src_eid  = SPDM_I2C_EID;
        s->resp_tag      = s->current_tag;
        s->resp_pending  = true;
        return;
    }

    /* stub: 0xFF trigger → 100-byte test response (kept for qtest) */
    if (s->msg_buf[0] == 0xFF) {
        memset(s->resp_buf, 0xAB, 100);
        s->resp_total    = 100;
        s->resp_offset   = 0;
        s->resp_next_seq = 0;
        s->resp_dst_eid  = s->peer_eid;
        s->resp_src_eid  = SPDM_I2C_EID;
        s->resp_tag      = s->current_tag;
        s->resp_pending  = true;
        return;
    }

    /* echo everything else */
    memcpy(s->resp_buf, s->msg_buf, s->msg_len);
    s->resp_total    = s->msg_len;
    s->resp_offset   = 0;
    s->resp_next_seq = 0;
    s->resp_dst_eid  = s->peer_eid;
    s->resp_src_eid  = SPDM_I2C_EID;
    s->resp_tag      = s->current_tag;
    s->resp_pending  = true;
}

/* Process one fully received MCTP packet */
static void spdm_i2c_process_packet(SpdmI2cState *dev)
{
    uint8_t flags   = dev->rx_mctp_hdr[3];
    bool    som     = !!(flags & MCTP_FLAG_SOM);
    bool    eom     = !!(flags & MCTP_FLAG_EOM);
    uint8_t pkt_seq = MCTP_SEQ(flags);
    uint8_t tag     = MCTP_TAG(flags);

    /* Reject oversized or truncated packets */
    if (dev->rx_oversized) {
        dev->assembling = false;
        return;
    }
    if (dev->rx_payload_len < dev->rx_payload_total) {
        /* truncated: fewer bytes arrived than byte_count promised */
        dev->assembling = false;
        return;
    }

    if (som) {
        dev->msg_len      = 0;
        dev->expected_seq = 0;
        dev->assembling   = true;
        dev->seq_error    = false;
        dev->peer_eid     = dev->rx_mctp_hdr[2]; /* src EID of requester */
        dev->current_tag  = tag;
    } else {
        if (!dev->assembling || pkt_seq != dev->expected_seq) {
            dev->seq_error  = true;
            dev->assembling = false;
            return;
        }
    }

    /* Accumulate payload into message buffer */
    int space = MCTP_MAX_MSG - dev->msg_len;
    int copy  = MIN(dev->rx_payload_len, space);
    memcpy(dev->msg_buf + dev->msg_len, dev->rx_payload, copy);
    dev->msg_len     += copy;
    dev->expected_seq = (dev->expected_seq + 1) & 0x3;

    if (eom && dev->assembling) {
        dev->assembling = false;
        spdm_i2c_handle_message(dev);
    }
}

/* ── libspdm transport callbacks ───────────────────────────── */

static SpdmI2cState *g_spdm_dev;

static libspdm_return_t spdm_send_message(void *ctx, size_t msg_size, const void *msg, uint64_t timeout)
{
    if (!g_spdm_dev || msg_size > MCTP_MAX_MSG)
        return LIBSPDM_STATUS_SEND_FAIL;
    memcpy(g_spdm_dev->spdm_response, msg, msg_size);
    g_spdm_dev->spdm_response_len = msg_size;
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t spdm_receive_message(void *ctx,
                                             size_t *msg_size,
                                             void **msg,
                                             uint64_t timeout)
{
    if (!g_spdm_dev || g_spdm_dev->msg_len == 0)
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    if (*msg_size < (size_t)g_spdm_dev->msg_len)
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
    memcpy(*msg, g_spdm_dev->msg_buf, g_spdm_dev->msg_len);
    *msg_size = (size_t)g_spdm_dev->msg_len;
    return LIBSPDM_STATUS_SUCCESS;
}

bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size)
{
    /*
     * spdm_device_secret_lib_sample calls us with relative paths like
     * "ecp256/end_responder.key" when signing for CHALLENGE_AUTH.
     * Redirect those to the configured cert-key property so the path
     * is fully controlled by the QEMU device options.
     */
    const char *path = file_name;
    if (g_spdm_dev && g_spdm_dev->cert_key_path &&
        !g_path_is_absolute(file_name) &&
        strstr(file_name, ".key") != NULL) {
        path = g_spdm_dev->cert_key_path;
    }

    GError *err = NULL;
    gsize sz = 0;
    gchar *buf = NULL;
    void *out;

    if (!g_file_get_contents(path, &buf, &sz, &err)) {
        if (err != NULL) {
            g_error_free(err);
        }
        return false;
    }

    out = malloc(sz);
    if (out == NULL) {
        g_free(buf);
        return false;
    }

    memcpy(out, buf, sz);
    g_free(buf);

    *file_data = out;
    *file_size = (size_t)sz;
    return true;
}

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size)
{
    GError *err = NULL;
    gboolean ok = g_file_set_contents(file_name,
                                      (const gchar *)file_data,
                                      (gssize)file_size,
                                      &err);
    if (!ok && err != NULL) {
        g_error_free(err);
    }
    return ok;
}

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
    /* Keep sample backend quiet during qtests; protocol traces are already logged. */
}



static uint8_t s_sender_buffer[SPDM_BUF_SIZE];
static uint8_t s_receiver_buffer[SPDM_BUF_SIZE];

static libspdm_return_t spdm_acquire_sender_buffer(void *ctx, void **buf)
{
    *buf = s_sender_buffer;
    return LIBSPDM_STATUS_SUCCESS;
}
static void spdm_release_sender_buffer(void *ctx, const void *buf) {}

static libspdm_return_t spdm_acquire_receiver_buffer(void *ctx, void **buf)
{
    *buf = s_receiver_buffer;
    return LIBSPDM_STATUS_SUCCESS;
}
static void spdm_release_receiver_buffer(void *ctx, const void *buf) {}

static void spdm_i2c_libspdm_init(SpdmI2cState *s)
{
    size_t ctx_size    = libspdm_get_context_size();
    size_t scratch_size;

    if (&g_private_key_mode) {
        g_private_key_mode = true;
    }

    s->spdm_ctx = g_malloc0(ctx_size);
    g_spdm_dev = s;
    libspdm_init_context(s->spdm_ctx);

    libspdm_register_transport_layer_func(
        s->spdm_ctx,
        MCTP_MAX_MSG,
        LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
        LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
        libspdm_transport_mctp_encode_message,
        libspdm_transport_mctp_decode_message);

    libspdm_register_device_io_func(s->spdm_ctx,
                                    spdm_send_message,
                                    spdm_receive_message);

    {
        libspdm_data_parameter_t p;
        uint8_t  u8;
        uint16_t u16;
        uint32_t u32;

        memset(&p, 0, sizeof(p));
        p.location = LIBSPDM_DATA_LOCATION_LOCAL;

        u32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP  |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP  |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP   |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
              SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &p, &u32, sizeof(u32));

        u8 = 0x0B;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &p, &u8, sizeof(u8));

        u8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_MEASUREMENT_SPEC, &p, &u8, sizeof(u8));

          u32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
          libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &p, &u32, sizeof(u32));

        u32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_BASE_ASYM_ALGO, &p, &u32, sizeof(u32));

        u32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_BASE_HASH_ALGO, &p, &u32, sizeof(u32));

        u16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_DHE_NAME_GROUP, &p, &u16, sizeof(u16));

        u16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &p, &u16, sizeof(u16));

        u16 = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
        libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_KEY_SCHEDULE, &p, &u16, sizeof(u16));
    }

        if (s->cert_chain_path) {
        gsize cert_sz;
        guchar *cert_data;
        GError *err = NULL;
        if (g_file_get_contents(s->cert_chain_path,
                                (gchar **)&cert_data, &cert_sz, &err)) {
            libspdm_data_parameter_t cp;
            uint8_t slot_mask = 0x1;
            memset(&cp, 0, sizeof(cp));
            cp.location = LIBSPDM_DATA_LOCATION_LOCAL;
            cp.additional_data[0] = 0;

            s->cert_chain_data = cert_data;
            s->cert_chain_size = cert_sz;

            libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                             &cp, s->cert_chain_data, s->cert_chain_size);
            libspdm_set_data(s->spdm_ctx, LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
                             &cp, &slot_mask, sizeof(slot_mask));
        } else {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "spdm-i2c: cert load failed: %s\n", err->message);
            g_error_free(err);
        }
    }

    libspdm_register_device_buffer_func(
        s->spdm_ctx,
        SPDM_BUF_SIZE, SPDM_BUF_SIZE,
        spdm_acquire_sender_buffer,  spdm_release_sender_buffer,
        spdm_acquire_receiver_buffer, spdm_release_receiver_buffer);



    scratch_size = libspdm_get_sizeof_required_scratch_buffer(s->spdm_ctx);
    s->spdm_scratch = g_malloc0(scratch_size);
    libspdm_set_scratch_buffer(s->spdm_ctx, s->spdm_scratch, scratch_size);

    s->spdm_ready = true;
}

/* Build the next outgoing MCTP packet into tx_buf */
static void spdm_i2c_build_next_packet(SpdmI2cState *dev)
{
    if (!dev->resp_pending) {
        dev->tx_len = 0;
        dev->tx_pos = 0;
        return;
    }

    I2CSlave *i2c    = I2C_SLAVE(dev);
    int  remaining   = dev->resp_total - dev->resp_offset;
    int  chunk       = MIN(remaining, MCTP_SMBUS_MTU);
    bool som         = (dev->resp_offset == 0);
    bool eom         = (chunk == remaining);
    uint8_t src_addr = (i2c->address << 1) | 1;
    uint8_t flags    = (som ? MCTP_FLAG_SOM : 0)
                     | (eom ? MCTP_FLAG_EOM : 0)
                     | ((dev->resp_next_seq & 0x3) << 4)
                     | (dev->resp_tag & 0x7);

    int i = 0;
    dev->tx_buf[i++] = 1 + 4 + chunk;   /* byte_count */
    dev->tx_buf[i++] = src_addr;
    dev->tx_buf[i++] = MCTP_HDR_VERSION;
    dev->tx_buf[i++] = dev->resp_dst_eid;
    dev->tx_buf[i++] = dev->resp_src_eid;
    dev->tx_buf[i++] = flags;
    memcpy(dev->tx_buf + i, dev->resp_buf + dev->resp_offset, chunk);
    i += chunk;

    dev->tx_len        = i;
    dev->tx_pos        = 0;
    dev->resp_offset  += chunk;
    dev->resp_next_seq = (dev->resp_next_seq + 1) & 0x3;

    if (eom) {
        dev->resp_pending = false;
    }
}

static int spdm_i2c_event(I2CSlave *s, enum i2c_event event)
{
    SpdmI2cState *dev = SPDM_I2C(s);

    switch (event) {
    case I2C_START_SEND:
        dev->rx_state        = RX_WAIT_CMD;
        dev->rx_mctp_hdr_pos = 0;
        dev->rx_payload_len  = 0;
        dev->rx_oversized    = false;
        break;
    case I2C_START_RECV:
        spdm_i2c_build_next_packet(dev);
        break;
    case I2C_FINISH:
        if (dev->rx_mctp_hdr_pos == 4) {
            spdm_i2c_process_packet(dev);
            /* Mark the packet consumed so read-side FINISH won't replay it. */
            dev->rx_mctp_hdr_pos = 0;
            dev->rx_payload_len = 0;
            dev->rx_payload_total = 0;
        }
        dev->rx_state = RX_WAIT_CMD;
        break;
    default:
        break;
    }
    return 0;
}

static uint8_t spdm_i2c_rx(I2CSlave *s)
{
    SpdmI2cState *dev = SPDM_I2C(s);

    if (dev->tx_pos < dev->tx_len) {
        return dev->tx_buf[dev->tx_pos++];
    }
    return 0xFF;
}

static int spdm_i2c_tx(I2CSlave *s, uint8_t data)
{
    SpdmI2cState *dev = SPDM_I2C(s);

    switch (dev->rx_state) {
    case RX_WAIT_CMD:
        if (data == MCTP_CMD_CODE) {
            dev->rx_state = RX_WAIT_BCNT;
        }
        break;
    case RX_WAIT_BCNT:
        dev->rx_byte_count    = data;
        dev->rx_payload_total = (int)data - 5;
        if (data > MCTP_MAX_BCNT) {
            dev->rx_oversized = true;
        }
        dev->rx_state = RX_WAIT_SRC;
        break;
    case RX_WAIT_SRC:
        dev->rx_src_addr = data;
        dev->rx_state    = RX_MCTP_HDR;
        break;
    case RX_MCTP_HDR:
        dev->rx_mctp_hdr[dev->rx_mctp_hdr_pos++] = data;
        if (dev->rx_mctp_hdr_pos == 4) {
            dev->rx_state = (dev->rx_payload_total > 0) ? RX_PAYLOAD
                                                        : RX_WAIT_CMD;
        }
        break;
    case RX_PAYLOAD:
        if (dev->rx_payload_len < MCTP_SMBUS_MTU) {
            dev->rx_payload[dev->rx_payload_len++] = data;
        }
        break;
    }
    return 0;
}

static void spdm_i2c_class_init(ObjectClass *klass, const void *data)
{
    I2CSlaveClass *k = I2C_SLAVE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->event = spdm_i2c_event;
    k->recv  = spdm_i2c_rx;
    k->send  = spdm_i2c_tx;

    dc->realize = spdm_i2c_realize;
    device_class_set_props(dc, spdm_i2c_props);
}

static void spdm_i2c_instance_init(Object *obj)
{
}

static void spdm_i2c_realize(DeviceState *dev, Error **errp)
{
    SpdmI2cState *s = SPDM_I2C(dev);
    spdm_i2c_libspdm_init(s);
}

static void spdm_i2c_instance_finalize(Object *obj)
{
    SpdmI2cState *s = SPDM_I2C(obj);
    g_free(s->spdm_ctx);
    g_free(s->spdm_scratch);
    g_free(s->cert_chain_data);
    g_free(s->cert_key_path);
}

static const TypeInfo spdm_i2c_info = {
    .name          = TYPE_SPDM_I2C,
    .parent        = TYPE_I2C_SLAVE,
    .instance_size = sizeof(SpdmI2cState),
    .instance_init = spdm_i2c_instance_init,
    .instance_finalize = spdm_i2c_instance_finalize,
    .class_init    = spdm_i2c_class_init,
};

static void spdm_i2c_register_types(void)
{
    type_register_static(&spdm_i2c_info);
}

type_init(spdm_i2c_register_types)
