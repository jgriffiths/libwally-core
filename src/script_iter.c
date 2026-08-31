#include "script.h"
#include "script_int.h"
#include "script_iter.h"
#include <include/wally_script.h>


bool si_init(script_iter *s, const unsigned char *script, size_t script_len)
{
    if (!s || !(s->script = script) ||
        script_len > 0xffffffff || !(s->script_len = script_len))
        return false;
    s->n = 0;
    return si_next(s);
}

bool si_next(script_iter *s)
{
    if (!s || si_is_error(s) || si_is_done(s))
        return false;

    /* Read the next opcode */
    s->opcode = s->script[s->n];
    s->data_n = 0;
    s->data_len = 0;

    {
        size_t written;
        if (script_is_op_n(s->opcode, /* allow_zero */ true, &written)) {
            /* OP_N */
            s->data_len = (uint32_t)written;
            ++s->n;
            s->opcode |= SI_NUMBER;
            return true;
        }
    }

    if (s->opcode >= 0x01 && s->opcode <= 0x04) {
        int64_t v;
        if (s->data_n + s->opcode + 1 > s->data_len ||
            scriptint_from_bytes(s->script + s->data_n, s->opcode + 1, &v) != WALLY_OK ||
            v > 0xffffffff)
            goto error;
        /* CScriptNum */
        s->data_len = (uint32_t)v;
        s->n += s->opcode + 1;
        s->opcode |= SI_NUMBER;
        return true;
    }

    switch (s->opcode) {
/* FIXME: Move to general PUSH handling */
        case HASH160_LEN:
        case EC_XONLY_PUBLIC_KEY_LEN: /* also SHA256_LEN */
        case EC_PUBLIC_KEY_LEN:
        case EC_PUBLIC_KEY_UNCOMPRESSED_LEN:
            /* PUSH of a hash or pubkey */
            if (s->data_n + s->opcode + 1 > s->data_len)
                goto error;
            s->data_len = s->opcode;
            s->data_n = s->n + 1;
            s->n += s->data_len + 1;
            s->opcode |= SI_PUSH;
            return true;
/* FIXME: Move to general PUSH handling */
        case OP_BOOLAND:
        case OP_BOOLOR:
        case OP_ADD:
        case OP_EQUAL:
        case OP_NUMEQUAL:
        case OP_CHECKSIG:
        case OP_CHECKSIGADD:
        case OP_CHECKMULTISIG:
        case OP_CHECKSEQUENCEVERIFY:
        case OP_CHECKLOCKTIMEVERIFY:
        case OP_FROMALTSTACK:
        case OP_TOALTSTACK:
        case OP_DROP:
        case OP_DUP:
        case OP_IF:
        case OP_IFDUP:
        case OP_NOTIF:
        case OP_ELSE:
        case OP_ENDIF:
        case OP_VERIFY:
        case OP_0NOTEQUAL:
        case OP_SIZE:
        case OP_SWAP:
        case OP_RIPEMD160:
        case OP_HASH160:
        case OP_SHA256:
        case OP_HASH256:
            /* Standard opcode */
            ++s->n;
            if (s->n < s->script_len && s->script[s->n] == OP_VERIFY) {
                /* OP_VERIFY must not follow an opcode it combines with */
                if (s->opcode == OP_EQUAL || s->opcode == OP_CHECKSIG || s->opcode == OP_CHECKMULTISIG)
                    goto error;
            }
            return true;
        default:
            break; /* Unknown/unsupported opcode */
    }

error:
    s->script = NULL;
    return false;
}

bool si_match(script_iter *src, const uint32_t *opcodes, size_t num_opcodes)
{
    if (!src || !opcodes || !num_opcodes)
        return false;

    script_iter s = *src;
    const uint32_t *opcodes_end = opcodes + num_opcodes;

    while (opcodes < opcodes_end) {
        if (si_is_error(src) || si_is_done(src) ||
            (*opcodes & (SI_NUMBER|SI_PUSH)) != (s.opcode & (SI_NUMBER|SI_PUSH)))
            return false;
        if (*opcodes & (SI_NUMBER|SI_PUSH)) {
            if (*opcodes & SI_EQUAL) {
                if (++opcodes >= opcodes_end || *opcodes != s.data_len)
                    return false;
            } else {
                if (*opcodes & SI_GTE)
                    if (++opcodes >= opcodes_end || *opcodes < s.data_len)
                        return false;
                if (*opcodes & SI_LTE)
                    if (++opcodes >= opcodes_end || *opcodes > s.data_len)
                        return false;
            }
        } else if (*opcodes != s.opcode)
            return false; /* Opcode mismtach */
        si_next(&s);
        ++opcodes;
    }
    return true; /* Matched all opcodes */
}
