#ifndef LIBWALLY_CORE_SCRIPT_ITER_H
#define LIBWALLY_CORE_SCRIPT_ITER_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Flags set in 'opcode' while iterating */
#define SI_NUMBER  0x0100 /* OP_[0-16] or scriptnum */
#define SI_PUSH    0x0200 /* Push of a hash or pubkey */

/* Flags set in 'opcodes' while matching */
#define SI_GTE     0x0400 /* Greater than or equal to the next value in opcodes */
#define SI_LTE     0x0800 /* Less than or equal to the next value in opcodes */
#define SI_EQUAL   0x1000 /* Equal to the next value in opcodes */

/* An iterator for parsing bitcoin script */
typedef struct {
    const unsigned char *script; /* Script being parsed, or NULL if an error occured */
    uint32_t script_len;         /* Length of 'script' */
    uint32_t n;                  /* Position of the next opcode in 'script' */
    uint32_t data_n;             /* Data position for the current push opcode */
    uint32_t data_len;           /* Push size or the number (if opcode & OP_NUM) */
    uint16_t opcode;             /* Current opcode plus SI_ flags */
} script_iter;

bool si_init(script_iter *s, const unsigned char *script, size_t script_len);
bool si_next(script_iter *s);
bool si_match(script_iter *s, const uint32_t *opcodes, size_t num_opcodes);

static inline bool si_is_done(script_iter *s) { return s->n >= s->script_len; }
static inline bool si_is_error(script_iter *s) { return !s->script; }

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SCRIPT_ITER_H */
