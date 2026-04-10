/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         libxlio_yyparse
#define yylex           libxlio_yylex
#define yyerror         libxlio_yyerror
#define yydebug         libxlio_yydebug
#define yynerrs         libxlio_yynerrs
#define yylval          libxlio_yylval
#define yychar          libxlio_yychar

/* First part of user prologue.  */
#line 13 "src/core/util/config_parser.y"


/* header section */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <util/libxlio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

typedef enum
{
	CONF_RULE
} configuration_t;

#define YYERROR_VERBOSE 1

extern int yyerror(const char *msg);
extern int yylex(void);
static int parse_err = 0;

struct dbl_lst	__instance_list;

/* some globals to store intermidiate parser state */
static struct use_family_rule __xlio_rule;
static struct address_port_rule *__xlio_address_port_rule = NULL;
static int __xlio_rule_push_head = 0;
static int current_role = 0;
static configuration_t current_conf_type = CONF_RULE;
static struct instance *curr_instance = NULL;

int __xlio_config_empty(void)
{
	return ((__instance_list.head == NULL) && (__instance_list.tail == NULL));
}

/* define the address by 4 integers */
static void __xlio_set_ipv4_addr(short a0, short a1, short a2, short a3)
{
	char buf[32];
	struct in_addr *p_ipv4 = NULL;
  
	p_ipv4 = &(__xlio_address_port_rule->ipv4);
  
	sprintf(buf,"%d.%d.%d.%d", a0, a1, a2, a3);
	if (1 != inet_pton(AF_INET, (const char*)buf, p_ipv4)) {
		parse_err = 1;
		yyerror("provided address is not legal");
	}
}

static void __xlio_set_inet_addr_prefix_len(unsigned char prefixlen)
{
	if (prefixlen > 32)
		prefixlen = 32;
	
	__xlio_address_port_rule->prefixlen = prefixlen;
}

// SM: log part is  not used...
int __xlio_min_level = 9;

void __xlio_dump_address_port_rule_config_state(char *buf) {
	if (__xlio_address_port_rule->match_by_addr) {
		char str_addr[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &(__xlio_address_port_rule->ipv4), str_addr, sizeof(str_addr));
		if ( __xlio_address_port_rule->prefixlen != 32 ) {
 			sprintf(buf+strlen(buf), " %s/%d", str_addr,
					__xlio_address_port_rule->prefixlen);
		} else {
			sprintf(buf+strlen(buf), " %s", str_addr);
		}
	} else {
		sprintf(buf+strlen(buf), " *");
	}
	
	if (__xlio_address_port_rule->match_by_port) {
		sprintf(buf+strlen(buf), ":%d",__xlio_address_port_rule->sport);
		if (__xlio_address_port_rule->eport > __xlio_address_port_rule->sport) 
			sprintf(buf+strlen(buf), "-%d",__xlio_address_port_rule->eport);
	}
	else
		sprintf(buf+strlen(buf), ":*");
}

/* dump the current state in readable format */
static void  __xlio_dump_rule_config_state() {
	char buf[1024];
	sprintf(buf, "\tACCESS CONFIG: use %s %s %s ", 
			__xlio_get_transport_str(__xlio_rule.target_transport), 
			__xlio_get_role_str(current_role),
			__xlio_get_protocol_str(__xlio_rule.protocol));
	__xlio_address_port_rule = &(__xlio_rule.first);
	__xlio_dump_address_port_rule_config_state(buf);
	if (__xlio_rule.use_second) {
		__xlio_address_port_rule = &(__xlio_rule.second);
		__xlio_dump_address_port_rule_config_state(buf);
	}
	sprintf(buf+strlen(buf), "\n");
	__xlio_log(1, "%s", buf);
}

/* dump configuration properites of new instance */
static void  __xlio_dump_instance() {
	char buf[1024];
	
	if (curr_instance) {
		sprintf(buf, "CONFIGURATION OF INSTANCE ");
		if (curr_instance->id.prog_name_expr)
			sprintf(buf+strlen(buf), "%s ", curr_instance->id.prog_name_expr);
		if (curr_instance->id.user_defined_id)
			sprintf(buf+strlen(buf), "%s", curr_instance->id.user_defined_id);
		sprintf(buf+strlen(buf), ":\n");
		__xlio_log(1, "%s", buf);
	}
}

static void __xlio_add_dbl_lst_node_head(struct dbl_lst *lst, struct dbl_lst_node *node)
{
	if (node && lst) {
	
		node->prev = NULL;
		node->next = lst->head;
		
		if (!lst->head)
			lst->tail = node;
		else 
			lst->head->prev = node;	
					
		lst->head = node;
	}
}

static void __xlio_add_dbl_lst_node(struct dbl_lst *lst, struct dbl_lst_node *node)
{
	if (node && lst) {
		node->prev = lst->tail;
	
		if (!lst->head) 
			lst->head = node;
		else 
			lst->tail->next = node;
		lst->tail = node;
	}
}

static struct dbl_lst_node* __xlio_allocate_dbl_lst_node()
{
	struct dbl_lst_node *ret_val = NULL;
	
	ret_val = (struct dbl_lst_node*) malloc(sizeof(struct dbl_lst_node));
	if (!ret_val) {
		yyerror("fail to allocate new node");
		parse_err = 1;		
	}
	else
		memset((void*) ret_val, 0, sizeof(struct dbl_lst_node));	
	return ret_val;
}

/* use the above state for adding a new instance */
static void __xlio_add_instance(char *prog_name_expr, char *user_defined_id) {
	struct dbl_lst_node *curr, *new_node;
	struct instance *new_instance;
  
	curr = __instance_list.head;
	while (curr) {
		struct instance *instance = (struct instance*)curr->data;
		if (!strcmp(prog_name_expr, instance->id.prog_name_expr) && !strcmp(user_defined_id, instance->id.user_defined_id)) {
			curr_instance = (struct instance*)curr->data;
			if (__xlio_min_level <= 1) __xlio_dump_instance();
			return;  		
		}
		curr = curr->next;
	}
  
	if (!(new_node = __xlio_allocate_dbl_lst_node())) 
		return;
	
	new_instance = (struct instance*) malloc(sizeof(struct instance));
	if (!new_instance) {
		free(new_node);
		yyerror("fail to allocate new instance");
		parse_err = 1;
		return;
	}

	memset((void*) new_instance, 0, sizeof(struct instance));
	new_instance->id.prog_name_expr = strdup(prog_name_expr);
	new_instance->id.user_defined_id = strdup(user_defined_id);
  
	if (!new_instance->id.prog_name_expr || !new_instance->id.user_defined_id) {
		yyerror("failed to allocate memory");
		parse_err = 1;
		if (new_instance->id.prog_name_expr)
			free(new_instance->id.prog_name_expr);
		if (new_instance->id.user_defined_id)
			free(new_instance->id.user_defined_id);
		free(new_instance);
		return;
	}
	new_node->data = (void*)new_instance;
	__xlio_add_dbl_lst_node(&__instance_list, new_node);
	curr_instance = new_instance;
	if (__xlio_min_level <= 1) __xlio_dump_instance();
}

static void __xlio_add_inst_with_int_uid(char *prog_name_expr, int user_defined_id) {
	char str_id[50];
	sprintf(str_id, "%d", user_defined_id);
	__xlio_add_instance(prog_name_expr, str_id);
}

/* use the above state for making a new rule */
static void __xlio_add_rule() {
	struct dbl_lst *p_lst;
	struct use_family_rule *rule;
	struct dbl_lst_node *new_node;

	if (!curr_instance)
		__xlio_add_instance("*", "*");
  	if (!curr_instance)
		return;
  
	if (__xlio_min_level <= 1) __xlio_dump_rule_config_state();
	switch (current_role) {
	case ROLE_TCP_SERVER:
		p_lst = &curr_instance->tcp_srv_rules_lst;
		break;
	case ROLE_TCP_CLIENT:
		p_lst = &curr_instance->tcp_clt_rules_lst;
		break;
	case ROLE_UDP_SENDER:
		p_lst = &curr_instance->udp_snd_rules_lst;
		break;
	case ROLE_UDP_RECEIVER:
		p_lst = &curr_instance->udp_rcv_rules_lst;
		break;
	case ROLE_UDP_CONNECT:
		p_lst = &curr_instance->udp_con_rules_lst;
		break;
	default:
		yyerror("ignoring unknown role");
		parse_err = 1;
		return;
		break;
	}

	if (!(new_node = __xlio_allocate_dbl_lst_node())) 
		return;
	
	rule = (struct use_family_rule *)malloc(sizeof(*rule));
	if (!rule) {
		free(new_node);
		yyerror("fail to allocate new rule");
		parse_err = 1;
		return;
	}
	memset(rule, 0, sizeof(*rule));
	new_node->data = (void*)rule;
	*((struct use_family_rule *)new_node->data) = __xlio_rule; 
	if (__xlio_rule_push_head)
		__xlio_add_dbl_lst_node_head(p_lst, new_node);
	else
		__xlio_add_dbl_lst_node(p_lst, new_node);
}


#line 350 "third_party/legacy_config_parser/config_parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "config_parser.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_USE = 3,                        /* "use"  */
  YYSYMBOL_TCP_CLIENT = 4,                 /* "tcp client"  */
  YYSYMBOL_TCP_SERVER = 5,                 /* "tcp server"  */
  YYSYMBOL_UDP_SENDER = 6,                 /* "udp sender"  */
  YYSYMBOL_UDP_RECEIVER = 7,               /* "udp receiver"  */
  YYSYMBOL_UDP_CONNECT = 8,                /* "udp connect"  */
  YYSYMBOL_TCP = 9,                        /* "tcp"  */
  YYSYMBOL_UDP = 10,                       /* "udp"  */
  YYSYMBOL_OS = 11,                        /* "os"  */
  YYSYMBOL_XLIO = 12,                      /* "xlio"  */
  YYSYMBOL_SDP = 13,                       /* "sdp"  */
  YYSYMBOL_SA = 14,                        /* "sa"  */
  YYSYMBOL_INT = 15,                       /* "integer value"  */
  YYSYMBOL_APP_ID = 16,                    /* "application id"  */
  YYSYMBOL_PROGRAM = 17,                   /* "program name"  */
  YYSYMBOL_USER_DEFINED_ID_STR = 18,       /* "userdefined id str"  */
  YYSYMBOL_LOG = 19,                       /* "log statement"  */
  YYSYMBOL_DEST = 20,                      /* "destination"  */
  YYSYMBOL_STDERR = 21,                    /* "ystderr"  */
  YYSYMBOL_SYSLOG = 22,                    /* "syslog"  */
  YYSYMBOL_FILENAME = 23,                  /* "yfile"  */
  YYSYMBOL_NAME = 24,                      /* "a name"  */
  YYSYMBOL_LEVEL = 25,                     /* "min-level"  */
  YYSYMBOL_LINE = 26,                      /* "new line"  */
  YYSYMBOL_27_ = 27,                       /* '*'  */
  YYSYMBOL_28_ = 28,                       /* ':'  */
  YYSYMBOL_29_ = 29,                       /* '/'  */
  YYSYMBOL_30_ = 30,                       /* '.'  */
  YYSYMBOL_31_ = 31,                       /* '-'  */
  YYSYMBOL_YYACCEPT = 32,                  /* $accept  */
  YYSYMBOL_NL = 33,                        /* NL  */
  YYSYMBOL_ONL = 34,                       /* ONL  */
  YYSYMBOL_config = 35,                    /* config  */
  YYSYMBOL_statements = 36,                /* statements  */
  YYSYMBOL_statement = 37,                 /* statement  */
  YYSYMBOL_log_statement = 38,             /* log_statement  */
  YYSYMBOL_log_opts = 39,                  /* log_opts  */
  YYSYMBOL_log_dest = 40,                  /* log_dest  */
  YYSYMBOL_verbosity = 41,                 /* verbosity  */
  YYSYMBOL_app_id_statement = 42,          /* app_id_statement  */
  YYSYMBOL_app_id = 43,                    /* app_id  */
  YYSYMBOL_socket_statement = 44,          /* socket_statement  */
  YYSYMBOL_use = 45,                       /* use  */
  YYSYMBOL_transport = 46,                 /* transport  */
  YYSYMBOL_role = 47,                      /* role  */
  YYSYMBOL_tuple = 48,                     /* tuple  */
  YYSYMBOL_three_tuple = 49,               /* three_tuple  */
  YYSYMBOL_five_tuple = 50,                /* five_tuple  */
  YYSYMBOL_address_first = 51,             /* address_first  */
  YYSYMBOL_52_1 = 52,                      /* $@1  */
  YYSYMBOL_address_second = 53,            /* address_second  */
  YYSYMBOL_54_2 = 54,                      /* $@2  */
  YYSYMBOL_address = 55,                   /* address  */
  YYSYMBOL_ipv4 = 56,                      /* ipv4  */
  YYSYMBOL_ports = 57                      /* ports  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;


/* Second part of user prologue.  */
#line 319 "src/core/util/config_parser.y"

  long __xlio_config_line_num;

#line 445 "third_party/legacy_config_parser/config_parser.c"


#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  7
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   48

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  32
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  26
/* YYNRULES -- Number of rules.  */
#define YYNRULES  50
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  74

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   281


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,    27,     2,     2,    31,    30,    29,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    28,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   325,   325,   326,   327,   329,   330,   333,   336,   337,
     341,   342,   343,   347,   350,   351,   352,   356,   357,   358,
     362,   366,   370,   371,   376,   380,   384,   385,   386,   387,
     388,   393,   394,   395,   396,   397,   401,   402,   406,   410,
     414,   414,   418,   418,   422,   423,   424,   428,   432,   433,
     434
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "\"use\"",
  "\"tcp client\"", "\"tcp server\"", "\"udp sender\"", "\"udp receiver\"",
  "\"udp connect\"", "\"tcp\"", "\"udp\"", "\"os\"", "\"xlio\"", "\"sdp\"",
  "\"sa\"", "\"integer value\"", "\"application id\"", "\"program name\"",
  "\"userdefined id str\"", "\"log statement\"", "\"destination\"",
  "\"ystderr\"", "\"syslog\"", "\"yfile\"", "\"a name\"", "\"min-level\"",
  "\"new line\"", "'*'", "':'", "'/'", "'.'", "'-'", "$accept", "NL",
  "ONL", "config", "statements", "statement", "log_statement", "log_opts",
  "log_dest", "verbosity", "app_id_statement", "app_id",
  "socket_statement", "use", "transport", "role", "tuple", "three_tuple",
  "five_tuple", "address_first", "$@1", "address_second", "$@2", "address",
  "ipv4", "ports", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-25)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int8 yypact[] =
{
     -24,   -25,   -17,   -25,    12,   -25,    -2,   -25,   -25,    -1,
     -25,   -25,   -25,   -25,   -24,   -25,    -6,    13,    -7,   -17,
     -25,   -25,   -25,   -25,   -25,    19,   -25,   -25,    11,    -4,
     -17,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,
     -25,     6,   -25,   -24,   -25,   -25,    -8,   -12,   -25,   -17,
      -5,     5,   -25,   -25,     7,     8,   -25,     9,    23,    25,
      26,   -25,    14,   -25,   -25,    15,   -12,    27,    -5,   -25,
      16,   -25,    30,   -25
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       4,     2,     6,     8,     0,     3,     7,     1,    25,     0,
      14,     9,    10,    11,     4,    12,     0,     0,     4,    21,
      26,    27,    28,    29,    30,     0,    23,    22,     0,     0,
      13,    15,    16,    32,    31,    34,    33,    35,    40,    17,
      18,     0,    20,     4,    36,    37,     0,     0,    19,    24,
       0,     0,    46,    41,    44,    48,    50,    38,     0,     0,
       0,    42,     0,    45,    49,     0,     0,     0,     0,    43,
       0,    39,     0,    47
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -25,   -14,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,
     -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,   -25,
     -25,   -25,   -25,   -19,   -25,   -20
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     2,     3,     4,     6,    11,    12,    18,    31,    32,
      13,    14,    15,    16,    25,    38,    43,    44,    45,    46,
      47,    65,    66,    53,    54,    57
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
      19,     8,     1,    51,    30,    20,    21,    22,    23,     5,
      55,    42,     7,    28,     9,    52,    17,    10,    29,     1,
      50,    24,    56,    33,    34,    35,    36,    37,    26,    49,
      48,    27,    39,    40,    41,    58,    59,    61,    62,    60,
      63,    64,    70,    68,    67,    73,    72,    69,    71
};

static const yytype_int8 yycheck[] =
{
      14,     3,    26,    15,    18,    11,    12,    13,    14,    26,
      15,    15,     0,    20,    16,    27,    17,    19,    25,    26,
      28,    27,    27,     4,     5,     6,     7,     8,    15,    43,
      24,    18,    21,    22,    23,    30,    29,    28,    15,    31,
      15,    15,    15,    28,    30,    15,    30,    66,    68
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    26,    33,    34,    35,    26,    36,     0,     3,    16,
      19,    37,    38,    42,    43,    44,    45,    17,    39,    33,
      11,    12,    13,    14,    27,    46,    15,    18,    20,    25,
      33,    40,    41,     4,     5,     6,     7,     8,    47,    21,
      22,    23,    15,    48,    49,    50,    51,    52,    24,    33,
      28,    15,    27,    55,    56,    15,    27,    57,    30,    29,
      31,    28,    15,    15,    15,    53,    54,    30,    28,    55,
      15,    57,    30,    15
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    32,    33,    33,    33,    34,    34,    35,    36,    36,
      37,    37,    37,    38,    39,    39,    39,    40,    40,    40,
      41,    42,    43,    43,    44,    45,    46,    46,    46,    46,
      46,    47,    47,    47,    47,    47,    48,    48,    49,    50,
      52,    51,    54,    53,    55,    55,    55,    56,    57,    57,
      57
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     2,     0,     0,     1,     2,     0,     2,
       1,     1,     1,     3,     0,     2,     2,     2,     2,     3,
       2,     2,     3,     3,     5,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     7,
       0,     2,     0,     2,     1,     3,     1,     7,     1,     3,
       1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 17: /* log_dest: "destination" "ystderr"  */
#line 356 "src/core/util/config_parser.y"
                                        { __xlio_log_set_log_stderr(); }
#line 1447 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 18: /* log_dest: "destination" "syslog"  */
#line 357 "src/core/util/config_parser.y"
                                        { __xlio_log_set_log_syslog(); }
#line 1453 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 19: /* log_dest: "destination" "yfile" "a name"  */
#line 358 "src/core/util/config_parser.y"
                                        { __xlio_log_set_log_file((yyvsp[0].sval)); }
#line 1459 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 20: /* verbosity: "min-level" "integer value"  */
#line 362 "src/core/util/config_parser.y"
                  { __xlio_log_set_min_level((yyvsp[0].ival)); }
#line 1465 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 22: /* app_id: "application id" "program name" "userdefined id str"  */
#line 370 "src/core/util/config_parser.y"
                                                {__xlio_add_instance((yyvsp[-1].sval), (yyvsp[0].sval));	if ((yyvsp[-1].sval)) free((yyvsp[-1].sval)); if ((yyvsp[0].sval)) free((yyvsp[0].sval));	}
#line 1471 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 23: /* app_id: "application id" "program name" "integer value"  */
#line 371 "src/core/util/config_parser.y"
                                                {__xlio_add_inst_with_int_uid((yyvsp[-1].sval), (yyvsp[0].ival));	if ((yyvsp[-1].sval)) free((yyvsp[-1].sval));		}
#line 1477 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 24: /* socket_statement: use transport role tuple NL  */
#line 376 "src/core/util/config_parser.y"
                                { __xlio_add_rule(); }
#line 1483 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 25: /* use: "use"  */
#line 380 "src/core/util/config_parser.y"
            { current_conf_type = CONF_RULE; }
#line 1489 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 26: /* transport: "os"  */
#line 384 "src/core/util/config_parser.y"
                { __xlio_rule.target_transport = TRANS_OS;	}
#line 1495 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 27: /* transport: "xlio"  */
#line 385 "src/core/util/config_parser.y"
                { __xlio_rule.target_transport = TRANS_XLIO;	}
#line 1501 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 28: /* transport: "sdp"  */
#line 386 "src/core/util/config_parser.y"
                { __xlio_rule.target_transport = TRANS_SDP;	}
#line 1507 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 29: /* transport: "sa"  */
#line 387 "src/core/util/config_parser.y"
                { __xlio_rule.target_transport = TRANS_SA;	}
#line 1513 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 30: /* transport: '*'  */
#line 388 "src/core/util/config_parser.y"
                { __xlio_rule.target_transport = TRANS_ULP;	}
#line 1519 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 31: /* role: "tcp server"  */
#line 393 "src/core/util/config_parser.y"
                        { current_role = ROLE_TCP_SERVER; 	__xlio_rule.protocol = PROTO_TCP; }
#line 1525 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 32: /* role: "tcp client"  */
#line 394 "src/core/util/config_parser.y"
                        { current_role = ROLE_TCP_CLIENT; 	__xlio_rule.protocol = PROTO_TCP; }
#line 1531 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 33: /* role: "udp receiver"  */
#line 395 "src/core/util/config_parser.y"
                        { current_role = ROLE_UDP_RECEIVER; __xlio_rule.protocol = PROTO_UDP; }
#line 1537 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 34: /* role: "udp sender"  */
#line 396 "src/core/util/config_parser.y"
                        { current_role = ROLE_UDP_SENDER;	__xlio_rule.protocol = PROTO_UDP; }
#line 1543 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 35: /* role: "udp connect"  */
#line 397 "src/core/util/config_parser.y"
                        { current_role = ROLE_UDP_CONNECT;	__xlio_rule.protocol = PROTO_UDP; }
#line 1549 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 40: /* $@1: %empty  */
#line 414 "src/core/util/config_parser.y"
        { __xlio_address_port_rule = &(__xlio_rule.first); __xlio_rule.use_second = 0; }
#line 1555 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 42: /* $@2: %empty  */
#line 418 "src/core/util/config_parser.y"
        { __xlio_address_port_rule = &(__xlio_rule.second); __xlio_rule.use_second = 1; }
#line 1561 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 44: /* address: ipv4  */
#line 422 "src/core/util/config_parser.y"
                       { if (current_conf_type == CONF_RULE) __xlio_address_port_rule->match_by_addr = 1; __xlio_set_inet_addr_prefix_len(32); }
#line 1567 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 45: /* address: ipv4 '/' "integer value"  */
#line 423 "src/core/util/config_parser.y"
                       { if (current_conf_type == CONF_RULE) __xlio_address_port_rule->match_by_addr = 1; __xlio_set_inet_addr_prefix_len((yyvsp[0].ival)); }
#line 1573 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 46: /* address: '*'  */
#line 424 "src/core/util/config_parser.y"
                       { if (current_conf_type == CONF_RULE) __xlio_address_port_rule->match_by_addr = 0; __xlio_set_inet_addr_prefix_len(32); }
#line 1579 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 47: /* ipv4: "integer value" '.' "integer value" '.' "integer value" '.' "integer value"  */
#line 428 "src/core/util/config_parser.y"
                                    { __xlio_set_ipv4_addr((yyvsp[-6].ival),(yyvsp[-4].ival),(yyvsp[-2].ival),(yyvsp[0].ival)); }
#line 1585 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 48: /* ports: "integer value"  */
#line 432 "src/core/util/config_parser.y"
                      { __xlio_address_port_rule->match_by_port = 1; __xlio_address_port_rule->sport= (yyvsp[0].ival); __xlio_address_port_rule->eport= (yyvsp[0].ival); }
#line 1591 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 49: /* ports: "integer value" '-' "integer value"  */
#line 433 "src/core/util/config_parser.y"
                      { __xlio_address_port_rule->match_by_port = 1; __xlio_address_port_rule->sport= (yyvsp[-2].ival); __xlio_address_port_rule->eport= (yyvsp[0].ival); }
#line 1597 "third_party/legacy_config_parser/config_parser.c"
    break;

  case 50: /* ports: '*'  */
#line 434 "src/core/util/config_parser.y"
                      { __xlio_address_port_rule->match_by_port = 0; __xlio_address_port_rule->sport= 0;  __xlio_address_port_rule->eport= 0;  }
#line 1603 "third_party/legacy_config_parser/config_parser.c"
    break;


#line 1607 "third_party/legacy_config_parser/config_parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 437 "src/core/util/config_parser.y"


int yyerror(const char *msg)
{
	/* replace the $undefined and $end if exists */
	char *orig_msg = (char*)malloc(strlen(msg)+25);
	char *final_msg = (char*)malloc(strlen(msg)+25);

	strcpy(orig_msg, msg);
	
	char *word = strtok(orig_msg, " ");
	final_msg[0] = '\0';
	while (word != NULL) {
		if (!strncmp(word, "$undefined", 10)) {
			strcat(final_msg, "unrecognized-token ");
		} else if (!strncmp(word, "$end",4)) {
			strcat(final_msg, "end-of-file ");
		} else {
			strcat(final_msg, word);
			strcat(final_msg, " ");
		}
		word = strtok(NULL, " ");
	}
	
	__xlio_log(9, "Error (line:%ld) : %s\n", __xlio_config_line_num, final_msg);
	parse_err = 1;
	
	free(orig_msg);
	free(final_msg);
	return 1;
}

#include <unistd.h>
#include <errno.h>

/* parse apollo route dump file */
int __xlio_parse_config_file (const char *fileName) {
	extern FILE * libxlio_yyin;
   
	/* open the file */
	if (access(fileName, R_OK)) {
		printf("libxlio Error: No access to open File:%s %s\n", 
				fileName, strerror(errno));
		return(1);
	}

	libxlio_yyin = fopen(fileName,"r");
	if (!libxlio_yyin) {
		printf("libxlio Error: Fail to open File:%s\n", fileName);
		return(1);
	}
	__instance_list.head = NULL;
	__instance_list.tail = NULL;
	parse_err = 0;
	__xlio_config_line_num = 1;

	/* parse it */
	yyparse();

	fclose(libxlio_yyin);
	return(parse_err);
}

int __xlio_parse_config_line (const char *line) {
	extern FILE * libxlio_yyin;
	
	__xlio_rule_push_head = 1;
	
	libxlio_yyin = fmemopen((void *)line, strlen(line), "r");
	
	if (!libxlio_yyin) {
		printf("libxlio Error: Fail to parse line:%s\n", line);
		return(1);
	}
	
	parse_err = 0;
	yyparse();
	
	fclose(libxlio_yyin);
	
	return(parse_err);
}
