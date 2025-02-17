//go:build cgo

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netlink/route/route.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include<sys/socket.h>
#include <netlink/route/link.h>
#include<netlink/attr.h>

#ifndef RTA_ENCAP
#define RTA_ENCAP 22
#endif

/* --- 定数・型定義 --- */

/* BGP FlowSpecの各トークン（例示） */
typedef enum BGPFlowSpecType {
    BGPFlowSpecType_UNKNOWN      = 0,
    BGPFlowSpecType_DST_PREFIX   = 1,
    BGPFlowSpecType_SRC_PREFIX   = 2,
    BGPFlowSpecType_IP_PROTO     = 3,
    BGPFlowSpecType_PORT         = 4,
    BGPFlowSpecType_DST_PORT     = 5,
    BGPFlowSpecType_SRC_PORT     = 6,
    BGPFlowSpecType_ICMP_TYPE    = 7,
    BGPFlowSpecType_ICMP_CODE    = 8,
    BGPFlowSpecType_TCP_FLAG     = 9,
    BGPFlowSpecType_PKT_LEN      = 10,
    BGPFlowSpecType_DSCP         = 11,
    BGPFlowSpecType_IP_FRAGMENT  = 12,
    BGPFlowSpecType_FLOW_LABEL   = 13,
    /* 演算子 */
    BGPFlowSpecType_AND          = 0xf0,
    BGPFlowSpecType_OR           = 0xf1,
    BGPFlowSpecType_EQ           = 0xf2,
    BGPFlowSpecType_NEQ          = 0xf3,
    BGPFlowSpecType_GT           = 0xf4,
    BGPFlowSpecType_GTE          = 0xf5,
    BGPFlowSpecType_LS           = 0xf6,
    BGPFlowSpecType_LSE          = 0xf7,
    /* 値 */
    BGPFlowSpecType_TRUE         = 0xf8,
    BGPFlowSpecType_FALSE        = 0xf9,
    BGPFlowSpecType_PREFIX_VALUE = 0xfa,
    BGPFlowSpecType_VALUE        = 0xfb,
} BGPFlowSpecType;

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

/* 拡張属性としてFlowSpec条件を設定する際の属性番号（例示） */
#define FLOW_SPEC_ATTR_FILTER 100

/* SRv6エンキャップ用属性・モード（実際はincludeファイル等で定義される） */


/* --- AST構築用関数 --- */
void free_ast(ASTNode *node);

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

/* --- SRv6エンキャップ付きルート作成用関数 --- */

/*
 * 引数:
 *  - filter: バイト列としてのFlowSpecフィルター、長さはfilter_len
 *  - sids: エンキャップするSIDの配列（各SIDは16バイト）
 *  - sid_count: SIDの個数
 *
 * 条件に合致するパケット（netfilter forward hookでマッチ）に対して、
 * SRv6のencap（encap seg6 mode encap ...）を行うルートを
 * netlink経由でカーネルへ通知する。
 */
int setup_srv6_encap_filter(const unsigned char *filter, size_t filter_len,
                            const unsigned char **sids, size_t sid_count)
{
    int err = 0;
    size_t offset = 0;
    ASTNode *ast = parse_ast(filter, filter_len, &offset);
    if (!ast) {
        fprintf(stderr, "Failed to parse filter AST\n");
        return -EINVAL;
    }

    char *filter_str = ast_to_string(ast);
    if (!filter_str) {
        free_ast(ast);
        return -ENOMEM;
    }
    printf("Parsed filter AST: %s\n", filter_str);



    /* ネットリンクソケット作成 */
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        free(filter_str);
        free_ast(ast);
        return -ENOMEM;
    }
    if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0) {
        fprintf(stderr, "nl_connect error: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        free(filter_str);
        free_ast(ast);
        return err;
    }

    /* ルートオブジェクト作成（SRv6はIPv6ルートとする） */
    struct rtnl_route *route = rtnl_route_alloc();
    if (!route) {
        nl_socket_free(sock);
        free(filter_str);
        free_ast(ast);
        return -ENOMEM;
    }
    rtnl_route_set_family(route, AF_INET6);
    rtnl_route_set_table(route, RT_TABLE_MAIN);
    rtnl_route_set_protocol(route, RTPROT_STATIC);
    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    /* ここでは例として全トラフィック対象（dst prefix ::/0）とする */
    struct nl_addr *dst = NULL;
    if ((err = nl_addr_parse("::/0", AF_INET6, &dst)) < 0) {
        fprintf(stderr, "nl_addr_parse error: %s\n", nl_geterror(err));
        rtnl_route_put(route);
        nl_socket_free(sock);
        free(filter_str);
        free_ast(ast);
        return err;
    }
    rtnl_route_set_dst(route, dst);
    nl_addr_put(dst);

    rtnl_route_set_type(route,RTA_ENCAP);
    
    /* seg6 mode: encap */
    /* SIDリストを追加 */

 
    /* ルートにencap情報を設定 *

    /* ルート追加メッセージを作成 */
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        rtnl_route_put(route);
        nl_socket_free(sock);
        free(filter_str);
        free_ast(ast);
        return -ENOMEM;
    }
    /* RTM_NEWROUTEメッセージとして構築 */
    if ((err = rtnl_route_build_msg(msg,route)) < 0) {
        fprintf(stderr, "rtnl_route_build_msg error: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        rtnl_route_put(route);
        nl_socket_free(sock);
        free(filter_str);
        free_ast(ast);
        return err;
    }

    /* メッセージ送信 */
    if ((err = nl_send_auto(sock, msg)) < 0) {
        fprintf(stderr, "nl_send_auto_complete error: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        rtnl_route_put(route);
        nl_socket_free(sock);
        free(filter_str);
        free_ast(ast);
        return err;
    }

    /* 応答待ち（必要に応じて） */
    nlmsg_free(msg);
    rtnl_route_put(route);
    nl_socket_free(sock);
    free(filter_str);
    free_ast(ast);
    return 0;
}


int main(void)
{
    /* 例: フィルター = "DST_PREFIX EQ PREFIX_VALUE(...)" を前置記法で構築
     *
     * バイト列例（各トークンは1バイト）：
     *   [ DST_PREFIX, EQ, PREFIX_VALUE, <prefix_len>, <prefix bytes> ]
     *
     * ここでは、DST_PREFIX (0x01) EQ (0xf2) PREFIX_VALUE (0xfa),
     * prefix_len = 64, prefix = 0x20 0x01 0x0d 0xb8 ...（ここでは仮の値）
     */
    unsigned char filter_example[] = {
        BGPFlowSpecType_DST_PREFIX,
        BGPFlowSpecType_EQ,
        BGPFlowSpecType_PREFIX_VALUE,
        64, /* prefix length */
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00  /* 8バイト分（(64+7)/8） */
    };
    size_t filter_len = sizeof(filter_example);

    /* 例: SIDリスト（2件）。各SIDは16バイト */
    unsigned char sid1[16] = { /* SID1の16バイト値 */ 
        0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    unsigned char sid2[16] = { /* SID2の16バイト値 */
        0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
    };
    const unsigned char *sids[] = { sid1, sid2 };
    size_t sid_count = 2;

    if (setup_srv6_encap_filter(filter_example, filter_len, sids, sid_count) < 0) {
        fprintf(stderr, "setup_srv6_encap_filter failed\n");
        return EXIT_FAILURE;
    }
    printf("SRv6 encap route successfully installed\n");
    return EXIT_SUCCESS;
}
