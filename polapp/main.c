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
#include"flowspec_type.h"
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <linux/netfilter/nf_tables.h>
#include <netlink/route/nexthop.h>
#include"pol.h"

#ifndef RTA_ENCAP
#define RTA_ENCAP 22
#endif



/* 拡張属性としてFlowSpec条件を設定する際の属性番号（例示） */
#define FLOW_SPEC_ATTR_FILTER 100

/* SRv6エンキャップ用属性・モード（実際はincludeファイル等で定義される） */



/* --- SRv6エンキャップ付きルート作成用関数 --- */

// copy from nft-rule-add.c
struct nftnl_expr* add_payload(uint32_t base, uint32_t dreg,  uint32_t offset, uint32_t len)
{
    struct nftnl_expr *e;

    e = nftnl_expr_alloc("payload");
    if (e == NULL) {
        perror("expr payload oom");
        exit(EXIT_FAILURE);
    }

    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

    return e;
}

int get_field(ASTNode* node,size_t* len) {
    if(!node||node->kind!=AST_NODE_FIELD) {
        fprintf(stderr, "Invalid node\n");
        return -EINVAL;
    }
    switch(node->type){
        case BGPFlowSpecType_DST_PORT: {
            struct nftnl_expr * expr = add_payload(NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
                2 /*offset of dst port*/, sizeof(uint16_t));
            if (!expr) {
                fprintf(stderr, "Failed to add payload expr\n");
                return -ENOMEM;
            }
            *len=sizeof(uint16_t);
            return NFT_REG_1;
        }
        case BGPFlowSpecType_SRC_PORT: {
            struct nftnl_expr * expr = add_payload(NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
                0 /*offset of src port*/, sizeof(uint16_t));
            if (!expr) {
                fprintf(stderr, "Failed to add payload expr\n");
                return -ENOMEM;
            }
            *len=sizeof(uint16_t);
            return NFT_REG_1;
        }
        case BGPFlowSpecType_IP_PROTO: {
            struct nftnl_expr * expr = add_payload(NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                6 /*offset of next header*/, sizeof(uint8_t));
            if (!expr) {
                fprintf(stderr, "Failed to add payload expr\n");
                return -ENOMEM;
            }
            *len=sizeof(uint8_t);
            return NFT_REG_1;
        }
        case BGPFlowSpecType_SRC_PREFIX: {
            struct nftnl_expr * expr = add_payload(NFT_PAYLOAD_NETWORK_HEADER, NFT_REG32_00,
                12 /*offset of src prefix*/, sizeof(uint32_t));
            if (!expr) {
                fprintf(stderr, "Failed to add payload expr\n");
                return -ENOMEM;
            }
            *len=sizeof(uint32_t);
            return NFT_REG_1;
        }
    }
}

int mapOp(BGPFlowSpecType t){
    switch(t){
        case BGPFlowSpecType_EQ:
            return NFT_CMP_EQ;
        case BGPFlowSpecType_NEQ:
            return NFT_CMP_NEQ;
        case BGPFlowSpecType_GT:
            return NFT_CMP_GT;
        case BGPFlowSpecType_LS:
            return NFT_CMP_LT;
        case BGPFlowSpecType_GTE:
            return NFT_CMP_GTE;
        case BGPFlowSpecType_LSE:
            return NFT_CMP_LTE;
        default:
            return -EINVAL;
    }
}

struct nftnl_expr* get_expr(ASTNode* node) {
    switch(node->kind) {
        case AST_NODE_OPERATOR: {
            switch(node->type) {
                case BGPFlowSpecType_EQ:
                case BGPFlowSpecType_NEQ:
                case BGPFlowSpecType_GT:
                case BGPFlowSpecType_LS:
                case BGPFlowSpecType_GTE:
                case BGPFlowSpecType_LSE: {
                    if(node->left->kind != AST_NODE_FIELD) {
                        fprintf(stderr, "Left node is not field\n");
                        return NULL;
                    }
                    size_t len;
                    int sreg = get_field(node->left, &len);
                    if(node->right->kind != AST_NODE_VALUE) {
                        fprintf(stderr, "Right node is not value\n");
                        return NULL;
                    }
                    if(node->right->type==BGPFlowSpecType_PREFIX_VALUE){}
                    uint32_t value = node->right->data.value;
                    struct nftnl_expr * expr = nftnl_expr_alloc("cmp");
                    if (!expr) {
                        fprintf(stderr, "Failed to alloc cmp expr\n");
                        return NULL;
                    }
                    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, sreg);
                    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, mapOp(node->type));
                    if(len==sizeof(uint8_t)) {
                        nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &value, sizeof(uint8_t));
                    } else if(len==sizeof(uint16_t)) {
                        nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &value, sizeof(uint16_t));
                    } else if(len==sizeof(uint32_t)) {
                        nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &value, sizeof(uint32_t));
                    }
                    else{
                        fprintf(stderr, "Unknown field length\n");
                        return NULL;
                    }
                    return expr;
                }
                default: {
                    fprintf(stderr, "Unknown operator type\n");
                    return NULL;
                }
            }
            break;
        }
        case AST_NODE_VALUE: {
            fprintf(stderr, "Value node is not supported here\n");
            return NULL;
        }
        case AST_NODE_FIELD: {
            fprintf(stderr, "Field node is not supported here\n");
            return NULL;
        }
    }
}

int apply_and_expr(struct nftnl_rule* rule,ASTNode* node) {
    if (!node) return -EINVAL;
    int err = 0;
    switch(node->kind) {
        case AST_NODE_OPERATOR: {
            switch(node->type) {
                case BGPFlowSpecType_AND: {
                    if((err = apply_and_expr(rule, node->left)) < 0) {
                        fprintf(stderr, "nftnl_rule_add_expr error: %s\n", nl_geterror(err));
                        return err;
                    }
                    if((err = apply_and_expr(rule, node->right)) < 0) {
                        fprintf(stderr, "nftnl_rule_add_expr error: %s\n", nl_geterror(err));
                        return err;
                    }
                    break;
                }
                case BGPFlowSpecType_OR: {
                    fprintf(stderr, "OR operator is not supported here\n");
                    return -EINVAL;
                }
                default: {
                    struct nftnl_expr* expr = get_expr(node);
                    if (!expr) {
                        fprintf(stderr, "Failed to get expr\n");
                        return -ENOMEM;
                    }
                    nftnl_rule_add_expr(rule, expr);
                    break;
                }
            }
            break;
        }
        case AST_NODE_VALUE: {
            if(node->type == BGPFlowSpecType_TRUE) {
                return 0;
            }
            fprintf(stderr, "Value node is not supported here\n");
            return -EINVAL;
        }
        case AST_NODE_FIELD: {
            fprintf(stderr, "Field node is not supported here\n");
            return -EINVAL;
        }
    }
}

int apply_ast_to_netfilter(struct nftnl_rule* rule, ASTNode* node){
    if (!node) return -EINVAL;
    int err = 0;
    switch(node->kind) {
        case AST_NODE_OPERATOR: {
            switch(node->type) {
                case BGPFlowSpecType_AND: {
                    apply_and_expr(rule, node);
                }
            }
        }
    }
}

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
int setup_srv6_encap_filter(FlowSpecSRv6Policy* policy)
{
    /*
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
    */



    int err = 0;
    /* ネットリンクソケット作成 */
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        return -ENOMEM;
    }
    if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0) {
        fprintf(stderr, "nl_connect error: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return err;
    }

    /* ルートオブジェクト作成（SRv6はIPv6ルートとする） */
    struct rtnl_route *route = rtnl_route_alloc();
    if (!route) {
        nl_socket_free(sock);
        return -ENOMEM;
    }
    rtnl_route_set_family(route, AF_INET6);
    rtnl_route_set_table(route, 70); // 優先度高めで
    rtnl_route_set_protocol(route, RTPROT_STATIC);
    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    /* ここでは例として全トラフィック対象（dst prefix ::/0）とする */
    struct nl_addr *dst = nl_addr_alloc(16);
    if((err = nl_addr_set_binary_addr(dst,policy->redirect_to,16)) < 0) {
        fprintf(stderr, "nl_addr_set_binary_addr error: %s\n", nl_geterror(err));
        rtnl_route_put(route);
        nl_socket_free(sock);
        return err;
    }
    rtnl_route_set_dst(route, dst);
    nl_addr_put(dst);

    struct nl_nexthop *nh = rtnl_route_nh_alloc();
    


    rtnl_route_add_nexthop(route, nh);
    /* seg6 mode: encap */
    /* SIDリストを追加 */

 
    /* ルートにencap情報を設定 *

    /* ルート追加メッセージを作成 */
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        rtnl_route_put(route);
        nl_socket_free(sock);
        return -ENOMEM;
    }
    /* RTM_NEWROUTEメッセージとして構築 */
    if ((err = rtnl_route_build_msg(msg,route)) < 0) {
        fprintf(stderr, "rtnl_route_build_msg error: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        rtnl_route_put(route);
        nl_socket_free(sock);
        return err;
    }

    /* メッセージ送信 */
    if ((err = nl_send_auto(sock, msg)) < 0) {
        fprintf(stderr, "nl_send_auto_complete error: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        rtnl_route_put(route);
        nl_socket_free(sock);
        return err;
    }

    /* 応答待ち（必要に応じて） */
    nlmsg_free(msg);
    rtnl_route_put(route);
    nl_socket_free(sock);
    return 0;
}


int main(int argc, char *argv[])
{

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    FlowSpecSRv6Policy *policy = readFlowSpecSRv6Policy(fp);
    fclose(fp);
    if (!policy) {
        fprintf(stderr, "Failed to read FlowSpecSRv6Policy\n");
        return EXIT_FAILURE;
    }

    printFlowSpecSRv6Policy(policy);

    if(setup_srv6_encap_filter(policy) < 0){
        fprintf(stderr, "setup_srv6_encap_filter failed\n");
        freeFlowSpecSRv6Policy(policy);
        return EXIT_FAILURE;
    }

    freeFlowSpecSRv6Policy(policy);
    return EXIT_SUCCESS;
    /*
    /* 例: フィルター = "DST_PREFIX EQ PREFIX_VALUE(...)" を前置記法で構築
     *
     * バイト列例（各トークンは1バイト）：
     *   [ DST_PREFIX, EQ, PREFIX_VALUE, <prefix_len>, <prefix bytes> ]
     *
     * ここでは、DST_PREFIX (0x01) EQ (0xf2) PREFIX_VALUE (0xfa),
     * prefix_len = 64, prefix = 0x20 0x01 0x0d 0xb8 ...（ここでは仮の値）
     *
    unsigned char filter_example[] = {
        BGPFlowSpecType_DST_PREFIX,
        BGPFlowSpecType_EQ,
        BGPFlowSpecType_PREFIX_VALUE,
        64, /* prefix length *
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00  /* 8バイト分（(64+7)/8） *
    };
    size_t filter_len = sizeof(filter_example);

    /* 例: SIDリスト（2件）。各SIDは16バイト *
    unsigned char sid1[16] = { /* SID1の16バイト値 *
        0x20,0x01,0x0d,0xb8,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    unsigned char sid2[16] = { /* SID2の16バイト値 *
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
    */
}
