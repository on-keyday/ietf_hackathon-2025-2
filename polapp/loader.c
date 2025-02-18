#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include"flowspec_type.h"
#include"pol.h" 
#include<stdarg.h>
#include<string.h>

/* BGPFlowSpecTypeAndOp の定義（実際の値は仕様に依存しますが、ここでは例として） */
/* --- AST構築用関数 --- */
void free_ast(ASTNode *node);


/* FlowSpecSRv6Policy を解放する関数 */
void freeFlowSpecSRv6Policy(FlowSpecSRv6Policy *policy) {
    if (!policy) return;
    if (policy->sid_list)
        free(policy->sid_list);
    if (policy->filter) {
        free(policy->filter);
    }
    if (policy->parsed_filter) {
        free_ast(policy->parsed_filter);
    }
    free(policy);
}

ASTNode *parse_ast(const unsigned char *filter, size_t len, size_t *offset);

/* ファイルから FlowSpecSRv6Policy を読み込む関数 */
FlowSpecSRv6Policy *readFlowSpecSRv6Policy(FILE *fp) {
    FlowSpecSRv6Policy *policy = malloc(sizeof(FlowSpecSRv6Policy));
    if (!policy) {
        perror("malloc");
        return NULL;
    }
    policy->filter_len = 0;
    policy->filter = NULL;
    policy->sid_list = NULL;
    policy->parsed_filter = NULL;

    /* sid_len を 1 バイト読み込む */
    if (fread(&policy->sid_len, 1, 1, fp) != 1) {
        perror("Failed to read sid_len");
        free(policy);
        return NULL;
    }

    /* sid_list を読み込む */
    if (policy->sid_len > 0) {
        policy->sid_list = malloc(policy->sid_len * 16);
        if (!policy->sid_list) {
            perror("malloc sid_list");
            free(policy);
            return NULL;
        }
        for (uint8_t i = 0; i < policy->sid_len; i++) {
            if (fread(policy->sid_list[i], 1, 16, fp) != 16) {
                perror("Failed to read sid_list entry");
                freeFlowSpecSRv6Policy(policy);
                return NULL;
            }
        }
    }

    /* redirect_to を読み込む */
    if (fread(policy->redirect_to, 1, 16, fp) != 16) {
        perror("Failed to read redirect_to");
        freeFlowSpecSRv6Policy(policy);
        return NULL;
    }

    /* filterをバイト列としてファイル末尾まで読む*/
    while (1) {
        unsigned char buf[1024];
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n == 0) {
            if (feof(fp)) break;
            perror("fread");
            freeFlowSpecSRv6Policy(policy);
            return NULL;
        }
        unsigned char *new_filter = realloc(policy->filter, policy->filter_len + n);
        if (!new_filter) {
            perror("realloc");
            freeFlowSpecSRv6Policy(policy);
            return NULL;
        }
        policy->filter = new_filter;
        memcpy(policy->filter + policy->filter_len, buf, n);
        policy->filter_len += n;
    }

    /* フィルターをASTに変換 */
    size_t offset = 0;
    policy->parsed_filter = parse_ast(policy->filter, policy->filter_len, &offset);
    if (!policy->parsed_filter) {
        perror("Failed to parse filter AST");
        freeFlowSpecSRv6Policy(policy);
        return NULL;
    }

    return policy;
}

/* デバッグ用: FlowSpecSRv6Policy の内容を表示する */
void printFlowSpecSRv6Policy(const FlowSpecSRv6Policy *policy) {
    if (!policy) return;
    printf("sid_len: %u\n", policy->sid_len);
    for (uint8_t i = 0; i < policy->sid_len; i++) {
        printf("sid_list[%u]:", i);
        for (int j = 0; j < 16; j++) {
            printf(" %02x", policy->sid_list[i][j]);
        }
        printf("\n");
    }
    
}


/*
 * 再帰的にフィルターバイト列からASTを構築する。
 * 前置記法を想定し、各トークンは1バイト（値トークンの場合は後続バイトあり）とする。
 */
ASTNode *parse_ast(const unsigned char *filter, size_t len, size_t *offset)
{
    if (*offset >= len) {
        fprintf(stderr, "parse_ast: unexpected end of filter\n");
        return NULL;
    }

    uint8_t token = filter[*offset];
    (*offset)++;

    /* Fieldノード：値が1～13 */
    if (token >= BGPFlowSpecType_DST_PREFIX && token <= BGPFlowSpecType_FLOW_LABEL) {
        ASTNode *node = malloc(sizeof(ASTNode));
        if (!node) return NULL;
        node->kind = AST_NODE_FIELD;
        node->type = (BGPFlowSpecType)token;
        node->left = node->right = NULL;
        return node;
    }
    /* 演算子ノード：AND～LSE（0xf0～0xf7） */
    else if (token >= BGPFlowSpecType_AND && token <= BGPFlowSpecType_LSE) {
        ASTNode *node = malloc(sizeof(ASTNode));
        if (!node) return NULL;
        node->kind = AST_NODE_OPERATOR;
        node->type = (BGPFlowSpecType)token;
        /* 左右のオペランドを再帰的にパース */
        node->left = parse_ast(filter, len, offset);
        if (!node->left) { free(node); return NULL; }
        node->right = parse_ast(filter, len, offset);
        if (!node->right) { free_ast(node->left); free(node); return NULL; }
        return node;
    }
    /* 値ノード：TRUE/FALSE（0xf8/0xf9） */
    else if (token == BGPFlowSpecType_TRUE || token == BGPFlowSpecType_FALSE) {
        ASTNode *node = malloc(sizeof(ASTNode));
        if (!node) return NULL;
        node->kind = AST_NODE_VALUE;
        node->type = (BGPFlowSpecType)token;
        node->left = node->right = NULL;
        return node;
    }
    /* PREFIX_VALUE（0xfa）：後続にu8:prefix_lenおよびprefix */
    else if (token == BGPFlowSpecType_PREFIX_VALUE) {
        if (*offset >= len) {
            fprintf(stderr, "parse_ast: no prefix length\n");
            return NULL;
        }
        uint8_t prefix_len = filter[*offset];
        (*offset)++;
        size_t prefix_bytes = (prefix_len + 7) / 8;
        if (*offset + prefix_bytes > len) {
            fprintf(stderr, "parse_ast: not enough bytes for prefix\n");
            return NULL;
        }
        ASTNode *node = malloc(sizeof(ASTNode));
        if (!node) return NULL;
        node->kind = AST_NODE_VALUE;
        node->type = (BGPFlowSpecType)token;
        node->left = node->right = NULL;
        node->data.prefix.prefix_len = prefix_len;
        node->data.prefix.prefix = malloc(prefix_bytes);
        if (!node->data.prefix.prefix) { free(node); return NULL; }
        memcpy(node->data.prefix.prefix, filter + *offset, prefix_bytes);
        *offset += prefix_bytes;
        return node;
    }
    /* VALUE（0xfb）：後続にu16の値 */
    else if (token == BGPFlowSpecType_VALUE) {
        if (*offset + 2 > len) {
            fprintf(stderr, "parse_ast: not enough bytes for VALUE\n");
            return NULL;
        }
        uint16_t val = (filter[*offset] << 8) | filter[*offset + 1];
        *offset += 2;
        ASTNode *node = malloc(sizeof(ASTNode));
        if (!node) return NULL;
        node->kind = AST_NODE_VALUE;
        node->type = (BGPFlowSpecType)token;
        node->left = node->right = NULL;
        node->data.value = val;
        return node;
    }
    else {
        fprintf(stderr, "parse_ast: unknown token 0x%x\n", token);
        return NULL;
    }
}

/* ASTノードの解放 */
void free_ast(ASTNode *node)
{
    if (!node) return;
    if (node->kind == AST_NODE_OPERATOR) {
        free_ast(node->left);
        free_ast(node->right);
    } else if (node->kind == AST_NODE_VALUE && node->type == BGPFlowSpecType_PREFIX_VALUE) {
        free(node->data.prefix.prefix);
    }
    free(node);
}

/*
 * ASTを文字列化する（デバッグ用）。
 * ここでは再帰的に各ノードを文字列にして結合する。
 * （※asprintfはGNU拡張です）
 */
char *ast_to_string(ASTNode *node)
{
    if (!node)
        return strdup("NULL");
    char *result = NULL;
    switch (node->kind) {
    case AST_NODE_FIELD: {
        const char *s = NULL;
        switch (node->type) {
        case BGPFlowSpecType_DST_PREFIX:   s = "DST_PREFIX"; break;
        case BGPFlowSpecType_SRC_PREFIX:   s = "SRC_PREFIX"; break;
        case BGPFlowSpecType_IP_PROTO:     s = "IP_PROTO"; break;
        case BGPFlowSpecType_PORT:         s = "PORT"; break;
        case BGPFlowSpecType_DST_PORT:     s = "DST_PORT"; break;
        case BGPFlowSpecType_SRC_PORT:     s = "SRC_PORT"; break;
        case BGPFlowSpecType_ICMP_TYPE:    s = "ICMP_TYPE"; break;
        case BGPFlowSpecType_ICMP_CODE:    s = "ICMP_CODE"; break;
        case BGPFlowSpecType_TCP_FLAG:     s = "TCP_FLAG"; break;
        case BGPFlowSpecType_PKT_LEN:      s = "PKT_LEN"; break;
        case BGPFlowSpecType_DSCP:         s = "DSCP"; break;
        case BGPFlowSpecType_IP_FRAGMENT:  s = "IP_FRAGMENT"; break;
        case BGPFlowSpecType_FLOW_LABEL:   s = "FLOW_LABEL"; break;
        default: s = "UNKNOWN_FIELD"; break;
        }
        result = strdup(s);
        break;
    }
    case AST_NODE_OPERATOR: {
        char *lstr = ast_to_string(node->left);
        char *rstr = ast_to_string(node->right);
        const char *op = NULL;
        switch (node->type) {
        case BGPFlowSpecType_AND: op = "AND"; break;
        case BGPFlowSpecType_OR:  op = "OR"; break;
        case BGPFlowSpecType_EQ:  op = "EQ"; break;
        case BGPFlowSpecType_NEQ: op = "NEQ"; break;
        case BGPFlowSpecType_GT:  op = "GT"; break;
        case BGPFlowSpecType_GTE: op = "GTE"; break;
        case BGPFlowSpecType_LS:  op = "LS"; break;
        case BGPFlowSpecType_LSE: op = "LSE"; break;
        default: op = "UNKNOWN_OP"; break;
        }
        asprintf(&result, "(%s %s %s)", lstr, op, rstr);
        free(lstr);
        free(rstr);
        break;
    }
    case AST_NODE_VALUE: {
        if (node->type == BGPFlowSpecType_TRUE)
            result = strdup("TRUE");
        else if (node->type == BGPFlowSpecType_FALSE)
            result = strdup("FALSE");
        else if (node->type == BGPFlowSpecType_VALUE)
            asprintf(&result, "VALUE(%u)", node->data.value);
        else if (node->type == BGPFlowSpecType_PREFIX_VALUE) {
            size_t prefix_bytes = (node->data.prefix.prefix_len + 7) / 8;
            char *hex = malloc(prefix_bytes * 3);
            if (!hex)
                result = strdup("PREFIX_VALUE(error)");
            else {
                hex[0] = '\0';
                for (size_t i = 0; i < prefix_bytes; i++) {
                    char buf[4];
                    snprintf(buf, sizeof(buf), "%02x", node->data.prefix.prefix[i]);
                    strcat(hex, buf);
                    if (i < prefix_bytes - 1)
                        strcat(hex, ":");
                }
                asprintf(&result, "PREFIX_VALUE(len=%u, %s)", node->data.prefix.prefix_len, hex);
                free(hex);
            }
        } else
            result = strdup("UNKNOWN_VALUE");
        break;
    }
    default:
        result = strdup("UNKNOWN_NODE");
        break;
    }
    return result;
}


