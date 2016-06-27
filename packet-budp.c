#include "config.h"

#include <epan/packet.h>
#define BUDP_PORT 2016
#define FOO_FIRST_FLAG 0x01
#define FOO_SECOND_FLAG 0x01
#define FOO_ONEMORE_FLAG 0x01


static int proto_budp = -1;
static gint ett_budp = -1;
static int hf_budp_hdr_version = -1; // версия
static int hf_budp_hdr_type = -1; // тип
static int hf_budp_hdr_flags = -1; // флаги
static int hf_budp_hdr_bool = -1; // булевый флаг
static int hf_budp_pl_len = -1; // длина полезных данных
static int hf_budp_payload = -1; // полезные данные
// флаги
static int hf_budp_flags_first = -1;
static int hf_budp_flags_second = -1;
static int hf_budp_flags_onemore = -1;

// работа с выводом пакета
static void dissect_budp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

    static const value_string packettypes[] = {
        {1, "Ping request"},
        {2, "Ping acknowledgment"},
        {3, "Pring payload"},
        {0, NULL}
    };

    guint8 packet_version = tvb_get_guint8(tvb, 0);
    guint8 packet_type = tvb_get_guint8(tvb, 1);
    guint32 packet_pl_len = 0;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BUDP"); // заполнение столбца
    col_clear(pinfo->cinfo, COL_INFO); // очистка столбка

    if(tree){
        gint offset = 0;
        proto_item *ti = NULL;
        proto_tree *budp_tree = NULL;

        ti = proto_tree_add_item(tree, proto_budp, tvb, 0, -1, FALSE); // добавляем ветку в дерево с информацией о пакете
        budp_tree = proto_item_add_subtree(ti, ett_budp);

        // выдераем поля из пакета
        proto_tree_add_item(budp_tree, hf_budp_hdr_version, tvb, offset, 1, FALSE);
        offset++;
        // вывод инфомрации в зависимости от версии пакета
        switch(packet_version){
            case 1:
                col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s", val_to_str(packet_type, packettypes, "Unknown (0x%02x"));
                proto_item_append_text(ti, ", Type: %s", val_to_str(packet_type, packettypes, "Unknown (0x%02x"));
                proto_tree_add_item(budp_tree, hf_budp_hdr_type, tvb, offset, 1, FALSE);
                offset++;
                proto_tree_add_item(budp_tree, hf_budp_hdr_flags, tvb, offset, 1, FALSE);
                proto_tree_add_item(budp_tree, hf_budp_flags_first, tvb, offset, 1, FALSE);
                proto_tree_add_item(budp_tree, hf_budp_flags_second, tvb, offset, 1, FALSE);
                proto_tree_add_item(budp_tree, hf_budp_flags_onemore, tvb, offset, 1, FALSE);
                offset++;
                proto_tree_add_item(budp_tree, hf_budp_hdr_bool, tvb, offset, 1, FALSE);
                offset++;
                proto_tree_add_item(budp_tree, hf_budp_pl_len, tvb, offset, 4, FALSE);
                packet_pl_len = tvb_get_ntohl(tvb, offset);
                offset+=4;
                if(packet_pl_len){
                    proto_tree_add_item(budp_tree, hf_budp_payload, tvb, offset, -1, FALSE);
                }
            break;
            default:
                col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown version of BUDP protocol (0x%02x)", packet_version);
        }
    }
}

// регистрация протокола
void proto_register_budp(void){
    // ассоциации (именование версий и тип пакета)
    static const value_string packetversions[] = {
        {1, "Version 1"},
        {0, NULL}
    };
    static const value_string packettypes[] = {
        {1, "Ping request"},
        {2, "Ping acknowledgment"},
        {3, "Pring payload"},
        {0, NULL}
    };


    static hf_register_info hf[] = { // получение полей пакета в переменные
        { &hf_budp_hdr_version,
            {
               "BUDP Header Version", "budp.hdr.version",
                FT_UINT8, BASE_DEC,
                VALS(packetversions), 0x0,
                NULL, HFILL
            }
        }, { &hf_budp_hdr_type,
            {
                "BUDP Header Type", "budp.hdr.type",
                FT_UINT8, BASE_DEC,
                VALS(packettypes), 0x0,
                NULL, HFILL
            }
        }, { &hf_budp_hdr_flags,
            {
                "BUDP Header Flags", "budp.hdr.flags",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL
            }
        }, { &hf_budp_flags_first,
            {
                "BUDP First Flag", "budp.hdr.flags.first",
                FT_BOOLEAN, FT_INT8,
                NULL, FOO_FIRST_FLAG,
                NULL, HFILL
            }
        }, { &hf_budp_flags_second,
            {
                "BUDP Second Flag", "budp.hdr.flags.second",
                FT_BOOLEAN, FT_INT8,
                NULL, FOO_SECOND_FLAG,
                NULL, HFILL
            }
        }, { &hf_budp_flags_onemore,
            {
                "BUDP Onemore Flag", "budp.hdr.flags.onemore",
                FT_BOOLEAN, FT_INT8,
                NULL, FOO_ONEMORE_FLAG, // задание маски, по которой определяем флаг
                NULL, HFILL
            }
        }, { &hf_budp_hdr_bool,
            {
                "BUDP Header Boolean", "budp.hdr.bool",
                FT_BOOLEAN, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        }, { &hf_budp_pl_len,
            {
                "BUDP Payload Length", "budp.pl_len",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        }, { &hf_budp_payload,
            {
                "BUDP Payload", "budp.payload",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL
            }
        }
    };

    static gint *ett[] = { &ett_budp };

    proto_budp = proto_register_protocol( // регистрируем имена для протокола
        "BUDP protocol",
        "BUDP",
        "budp" );

    proto_register_field_array(proto_budp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

// расшифровка пакета
void proto_reg_handoff_budp(void){
    static dissector_handle_t budp_handle;
    budp_handle = create_dissector_handle(dissect_budp,proto_budp); // обработчик пакета
    dissector_add_uint("udp.port",BUDP_PORT,budp_handle); // на каком порту работает
}