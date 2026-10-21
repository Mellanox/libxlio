/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_LIBXLIO_YY_THIRD_PARTY_LEGACY_CONFIG_PARSER_CONFIG_PARSER_H_INCLUDED
# define YY_LIBXLIO_YY_THIRD_PARTY_LEGACY_CONFIG_PARSER_CONFIG_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int libxlio_yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    USE = 258,                     /* "use"  */
    TCP_CLIENT = 259,              /* "tcp client"  */
    TCP_SERVER = 260,              /* "tcp server"  */
    UDP_SENDER = 261,              /* "udp sender"  */
    UDP_RECEIVER = 262,            /* "udp receiver"  */
    UDP_CONNECT = 263,             /* "udp connect"  */
    TCP = 264,                     /* "tcp"  */
    UDP = 265,                     /* "udp"  */
    OS = 266,                      /* "os"  */
    XLIO = 267,                    /* "xlio"  */
    SDP = 268,                     /* "sdp"  */
    SA = 269,                      /* "sa"  */
    INT = 270,                     /* "integer value"  */
    APP_ID = 271,                  /* "application id"  */
    PROGRAM = 272,                 /* "program name"  */
    USER_DEFINED_ID_STR = 273,     /* "userdefined id str"  */
    LOG = 274,                     /* "log statement"  */
    DEST = 275,                    /* "destination"  */
    STDERR = 276,                  /* "ystderr"  */
    SYSLOG = 277,                  /* "syslog"  */
    FILENAME = 278,                /* "yfile"  */
    NAME = 279,                    /* "a name"  */
    LEVEL = 280,                   /* "min-level"  */
    LINE = 281                     /* "new line"  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 286 "src/core/util/config_parser.y"

  int        ival;
  char      *sval;

#line 95 "third_party/legacy_config_parser/config_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE libxlio_yylval;


int libxlio_yyparse (void);


#endif /* !YY_LIBXLIO_YY_THIRD_PARTY_LEGACY_CONFIG_PARSER_CONFIG_PARSER_H_INCLUDED  */
