/*license*/
#pragma once
#include <stddef.h>
#include <stdint.h>
#include"flowspec_type.h"
#include <stdio.h>
/* PrefixValue 構造体 */
typedef struct {
    uint8_t prefix_len;   // ビット単位
    uint8_t *prefix;      // (prefix_len+7)/8 バイトの配列
} PrefixValue;

/* Value 構造体 */
typedef struct {
    uint16_t value;
} Value;

/* Code 構造体 */
/*
typedef struct {
    uint8_t code;
    union {
        PrefixValue prefix_value;
        Value value;
    } data;
} Code;
*/

typedef struct Operand {
    uint8_t and;
    BGPFlowSpecType type; // operator
    union {
        PrefixValue prefix_value;
        Value value;
    } data;
} Operand;


typedef struct FilterNode {
    BGPFlowSpecType type; // field
    size_t n_operands;
    Operand *operands;
}FilterNode;

/* ASTノードの種類 */
typedef enum {
    AST_NODE_FIELD,
    AST_NODE_VALUE,
    AST_NODE_OPERATOR,
} ASTNodeKind;

/* ASTノードの構造体 */
typedef struct ASTNode {
    ASTNodeKind kind;
    BGPFlowSpecType type;
    /* operatorの場合は左右の子を持つ */
    struct ASTNode *left;
    struct ASTNode *right;
    union {
        /* VALUEの場合（BGPFlowSpecType_VALUE） */
        uint16_t value;
        /* PREFIX_VALUEの場合 */
        struct {
            uint8_t prefix_len;
            uint8_t *prefix; /* 動的に確保 */
        } prefix;
    } data;
} ASTNode;

/* FlowSpecSRv6Policy 構造体 */
typedef struct {
    uint8_t sid_len;
    /* sid_list: sid_len 個の 16 バイトのエントリ */
    uint8_t (*sid_list)[16];
    uint8_t redirect_to[16];
    /* filter: Code エントリの配列（個数は num_codes） */
    size_t filter_len;
    unsigned char *filter; // parsed at main.c
    ASTNode* parsed_filter;
} FlowSpecSRv6Policy;

FlowSpecSRv6Policy *readFlowSpecSRv6Policy(FILE *fp) ;
void printFlowSpecSRv6Policy(const FlowSpecSRv6Policy *policy);
void freeFlowSpecSRv6Policy(FlowSpecSRv6Policy *policy);