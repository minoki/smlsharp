
structure LexMLYACC
=
   struct
    structure UserDeclarations =
      struct
(* ML-Yacc Parser Generator (c) 1989 Andrew W. Appel, David R. Tarditi

   yacc.lex: Lexer specification

  2012-1-13 ohori
  %footer added for defuncteringing ml.grm.sml
 *)

structure Tokens = LrVals.Tokens
type pos = int
type token = Tokens.token
type lexresult = token

type lexarg = Header.inputSource
type arg = lexarg

open Tokens
val error = Header.error
val lineno = Header.lineno
val text = Header.text

val pcount = ref 0
val commentLevel = ref 0
val actionstart = ref 0

val eof = fn i => (if (!pcount)>0 then
			error i (!actionstart)
			      " eof encountered in action beginning here !"
		   else (); EOF(!lineno,!lineno))

val Add = fn s => (text := s::(!text))

local val dict = 
  [("%prec",PREC_TAG),
   ("%term",TERM),
   ("%nonterm",NONTERM), 
   ("%eop",PERCENT_EOP),
   ("%start",START),
   ("%prefer",PREFER),
   ("%subst",SUBST),
   ("%change",CHANGE),
   ("%keyword",KEYWORD),
   ("%name",NAME),
   ("%verbose",VERBOSE), 
   ("%nodefault",NODEFAULT),
   ("%value",VALUE), 
   ("%noshift",NOSHIFT),
   ("%header",PERCENT_HEADER),
   ("%footer",PERCENT_FOOTER), 
   ("%decompose",PERCENT_DECOMPOSE),
   ("%blocksize",PERCENT_BLOCKSIZE),
   ("%pure",PERCENT_PURE),
   ("%token_sig_info",PERCENT_TOKEN_SIG_INFO),
   ("%arg",PERCENT_ARG),
   ("%pos",PERCENT_POS)]
in
fun lookup (s,left,right) = let
       fun f ((a,d)::b) = if a=s then d(left,right) else f b
	 | f nil = UNKNOWN(s,left,right)
       in
	  f dict
       end
end

fun inc (ri as ref i) = (ri := i+1)
fun dec (ri as ref i) = (ri := i-1)

end (* end of user routines *)
exception LexError (* raised if illegal leaf action tried *)
structure Internal =
	struct

datatype yyfinstate = N of int
type statedata = {fin : yyfinstate list, trans: string}
(* transition & final state table *)
val tab = let
val s = [ 
 (0, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (1, 
"\015\015\015\015\015\015\015\015\015\015\022\015\015\021\015\015\
\\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\
\\015\015\015\015\015\019\015\015\017\015\015\015\015\015\015\015\
\\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\
\\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\
\\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\
\\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\
\\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\015\
\\015"
),
 (3, 
"\023\023\023\023\023\023\023\023\023\066\069\023\023\068\023\023\
\\023\023\023\023\023\023\023\023\023\023\023\023\023\023\023\023\
\\066\023\023\023\023\046\023\044\042\023\041\023\040\038\023\023\
\\036\036\036\036\036\036\036\036\036\036\035\023\023\023\023\023\
\\023\027\027\027\027\027\027\027\027\027\027\027\027\027\027\027\
\\027\027\027\027\027\027\027\027\027\027\027\023\023\023\023\023\
\\023\027\027\027\027\027\032\027\027\027\027\027\027\027\027\030\
\\027\027\027\027\027\027\027\027\027\027\027\026\025\024\023\023\
\\023"
),
 (5, 
"\070\070\070\070\070\070\070\070\070\070\022\070\070\075\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\074\070\070\070\070\070\072\071\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070"
),
 (7, 
"\076\076\076\076\076\076\076\076\076\078\022\076\076\080\076\076\
\\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\
\\078\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\
\\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\
\\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\
\\076\076\076\076\076\076\076\076\076\076\076\076\077\076\076\076\
\\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\
\\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\076\
\\076"
),
 (9, 
"\081\081\081\081\081\081\081\081\081\081\022\081\081\075\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\085\084\082\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081"
),
 (11, 
"\087\087\087\087\087\087\087\087\087\087\095\087\087\094\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\093\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\088\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087"
),
 (13, 
"\096\096\096\096\096\096\096\096\096\096\022\096\096\075\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\100\099\097\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096"
),
 (15, 
"\016\016\016\016\016\016\016\016\016\016\000\016\016\000\016\016\
\\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\
\\016\016\016\016\016\000\016\016\000\016\016\016\016\016\016\016\
\\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\
\\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\
\\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\
\\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\
\\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\016\
\\016"
),
 (17, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\018\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (19, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\020\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (21, 
"\000\000\000\000\000\000\000\000\000\000\022\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (27, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\028\000\000\000\000\000\000\029\000\
\\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\000\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\028\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\028\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\028\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\
\\000"
),
 (30, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\028\000\000\000\000\000\000\029\000\
\\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\000\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\028\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\028\
\\000\028\028\028\028\028\031\028\028\028\028\028\028\028\028\028\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\
\\000"
),
 (32, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\028\000\000\000\000\000\000\029\000\
\\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\000\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\028\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\028\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\033\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\
\\000"
),
 (33, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\028\000\000\000\000\000\000\029\000\
\\028\028\028\028\028\028\028\028\028\028\000\000\000\000\000\000\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\028\
\\028\028\028\028\028\028\028\028\028\028\028\000\000\000\000\028\
\\000\028\028\028\028\028\028\028\028\028\028\028\028\028\028\028\
\\028\028\034\028\028\028\028\028\028\028\028\000\000\000\000\000\
\\000"
),
 (36, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\037\037\037\037\037\037\037\037\037\037\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (38, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\039\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (42, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\043\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (44, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\045\000\000\000\000\000\000\000\000\
\\045\045\045\045\045\045\045\045\045\045\000\000\000\000\000\000\
\\000\045\045\045\045\045\045\045\045\045\045\045\045\045\045\045\
\\045\045\045\045\045\045\045\045\045\045\045\000\000\000\000\045\
\\000\045\045\045\045\045\045\045\045\045\045\045\045\045\045\045\
\\045\045\045\045\045\045\045\045\045\045\045\000\000\000\000\000\
\\000"
),
 (46, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\065\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\061\047\053\047\
\\047\047\048\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (47, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (48, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\049\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (49, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\050\047\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (50, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\051\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (51, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\052\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (53, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\054\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (54, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\055\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (55, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\056\047\047\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (56, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\057\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (57, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\058\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (58, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\059\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (59, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\060\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (61, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\062\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (62, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\063\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\047\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (63, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\047\
\\000\047\047\047\047\047\047\047\047\047\047\047\047\047\047\047\
\\047\047\047\047\064\047\047\047\047\047\047\000\000\000\000\000\
\\000"
),
 (66, 
"\000\000\000\000\000\000\000\000\000\067\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\067\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (68, 
"\000\000\000\000\000\000\000\000\000\000\069\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (70, 
"\070\070\070\070\070\070\070\070\070\070\000\070\070\000\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\000\070\070\070\070\070\000\000\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\070\
\\070"
),
 (72, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\073\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (78, 
"\000\000\000\000\000\000\000\000\000\079\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\079\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (81, 
"\081\081\081\081\081\081\081\081\081\081\000\081\081\000\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\000\000\000\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\081\
\\081"
),
 (82, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\083\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (85, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\086\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (87, 
"\087\087\087\087\087\087\087\087\087\087\000\087\087\000\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\000\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\000\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\087\
\\087"
),
 (88, 
"\000\000\000\000\000\000\000\000\000\090\092\000\000\091\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\090\000\089\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (91, 
"\000\000\000\000\000\000\000\000\000\000\092\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (94, 
"\000\000\000\000\000\000\000\000\000\000\095\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (96, 
"\096\096\096\096\096\096\096\096\096\096\000\096\096\000\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\000\000\000\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\096\
\\096"
),
 (97, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\098\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
 (100, 
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\101\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\\000"
),
(0, "")]
fun f x = x 
val s = map f (rev (tl (rev s))) 
exception LexHackingError 
fun look ((j,x)::r, i: int) = if i = j then x else look(r, i) 
  | look ([], i) = raise LexHackingError
fun g {fin=x, trans=i} = {fin=x, trans=look(s,i)} 
in Vector.fromList(map g 
[{fin = [], trans = 0},
{fin = [], trans = 1},
{fin = [], trans = 1},
{fin = [], trans = 3},
{fin = [], trans = 3},
{fin = [], trans = 5},
{fin = [], trans = 5},
{fin = [], trans = 7},
{fin = [], trans = 7},
{fin = [], trans = 9},
{fin = [], trans = 9},
{fin = [], trans = 11},
{fin = [], trans = 11},
{fin = [], trans = 13},
{fin = [], trans = 13},
{fin = [(N 11),(N 21)], trans = 15},
{fin = [(N 11)], trans = 15},
{fin = [(N 21)], trans = 17},
{fin = [(N 2)], trans = 0},
{fin = [(N 21)], trans = 19},
{fin = [(N 14)], trans = 0},
{fin = [(N 19),(N 21)], trans = 21},
{fin = [(N 19)], trans = 0},
{fin = [(N 100)], trans = 0},
{fin = [(N 42),(N 100)], trans = 0},
{fin = [(N 93),(N 100)], trans = 0},
{fin = [(N 40),(N 100)], trans = 0},
{fin = [(N 96),(N 100)], trans = 27},
{fin = [(N 96)], trans = 27},
{fin = [(N 83)], trans = 0},
{fin = [(N 96),(N 100)], trans = 30},
{fin = [(N 34),(N 96)], trans = 27},
{fin = [(N 96),(N 100)], trans = 32},
{fin = [(N 96)], trans = 33},
{fin = [(N 38),(N 96)], trans = 27},
{fin = [(N 91),(N 100)], trans = 0},
{fin = [(N 86),(N 100)], trans = 36},
{fin = [(N 86)], trans = 36},
{fin = [(N 100)], trans = 38},
{fin = [(N 49)], trans = 0},
{fin = [(N 44),(N 100)], trans = 0},
{fin = [(N 46),(N 100)], trans = 0},
{fin = [(N 98),(N 100)], trans = 42},
{fin = [(N 5)], trans = 0},
{fin = [(N 79),(N 100)], trans = 44},
{fin = [(N 79)], trans = 44},
{fin = [(N 100)], trans = 46},
{fin = [(N 76)], trans = 47},
{fin = [(N 76)], trans = 48},
{fin = [(N 76)], trans = 49},
{fin = [(N 76)], trans = 50},
{fin = [(N 76)], trans = 51},
{fin = [(N 62),(N 76)], trans = 47},
{fin = [(N 76)], trans = 53},
{fin = [(N 76)], trans = 54},
{fin = [(N 76)], trans = 55},
{fin = [(N 76)], trans = 56},
{fin = [(N 76)], trans = 57},
{fin = [(N 76)], trans = 58},
{fin = [(N 76)], trans = 59},
{fin = [(N 72),(N 76)], trans = 47},
{fin = [(N 76)], trans = 61},
{fin = [(N 76)], trans = 62},
{fin = [(N 76)], trans = 63},
{fin = [(N 55),(N 76)], trans = 47},
{fin = [(N 89)], trans = 0},
{fin = [(N 31),(N 100)], trans = 66},
{fin = [(N 31)], trans = 66},
{fin = [(N 26),(N 100)], trans = 68},
{fin = [(N 26)], trans = 0},
{fin = [(N 109)], trans = 70},
{fin = [(N 104)], trans = 0},
{fin = [(N 102)], trans = 72},
{fin = [(N 8)], trans = 0},
{fin = [(N 106)], trans = 0},
{fin = [(N 19)], trans = 21},
{fin = [(N 162)], trans = 0},
{fin = [(N 160),(N 162)], trans = 0},
{fin = [(N 158),(N 162)], trans = 78},
{fin = [(N 158)], trans = 78},
{fin = [(N 19),(N 162)], trans = 21},
{fin = [(N 120)], trans = 81},
{fin = [(N 111)], trans = 82},
{fin = [(N 114)], trans = 0},
{fin = [(N 111)], trans = 0},
{fin = [(N 111)], trans = 85},
{fin = [(N 117)], trans = 0},
{fin = [(N 143)], trans = 87},
{fin = [(N 135)], trans = 88},
{fin = [(N 146)], trans = 0},
{fin = [(N 155)], trans = 0},
{fin = [(N 152)], trans = 91},
{fin = [(N 152)], trans = 0},
{fin = [(N 133)], trans = 0},
{fin = [(N 140)], trans = 94},
{fin = [(N 140)], trans = 0},
{fin = [(N 131)], trans = 96},
{fin = [(N 122)], trans = 97},
{fin = [(N 125)], trans = 0},
{fin = [(N 122)], trans = 0},
{fin = [(N 122)], trans = 100},
{fin = [(N 128)], trans = 0}])
end
structure StartStates =
	struct
	datatype yystartstate = STARTSTATE of int

(* start state definitions *)

val A = STARTSTATE 3;
val CODE = STARTSTATE 5;
val COMMENT = STARTSTATE 9;
val EMPTYCOMMENT = STARTSTATE 13;
val F = STARTSTATE 7;
val INITIAL = STARTSTATE 1;
val STRING = STARTSTATE 11;

end
type result = UserDeclarations.lexresult
	exception LexerError (* raised if illegal leaf action tried *)
end

fun makeLexer yyinput =
let	val yygone0= ~1
	val yyb = ref "\n" 		(* buffer *)
	val yybl = ref 1		(*buffer length *)
	val yybufpos = ref 1		(* location of next character to use *)
	val yygone = ref yygone0	(* position in file of beginning of buffer *)
	val yydone = ref false		(* eof found yet? *)
	val yybegin = ref 1		(*Current 'start state' for lexer *)

	val YYBEGIN = fn (Internal.StartStates.STARTSTATE x) =>
		 yybegin := x

fun lex (yyarg as (inputSource)) =
let fun continue() : Internal.result = 
  let fun scan (s,AcceptingLeaves : Internal.yyfinstate list list,l,i0) =
	let fun action (i,nil) = raise LexError
	| action (i,nil::l) = action (i-1,l)
	| action (i,(node::acts)::l) =
		case node of
		    Internal.N yyk => 
			(let fun yymktext() = substring(!yyb,i0,i-i0)
			     val yypos = i0+ !yygone
			open UserDeclarations Internal.StartStates
 in (yybufpos := i; case yyk of 

			(* Application actions *)

  100 => let val yytext=yymktext() in UNKNOWN(yytext,!lineno,!lineno) end
| 102 => let val yytext=yymktext() in inc pcount; Add yytext; continue() end
| 104 => let val yytext=yymktext() in dec pcount;
		    if !pcount = 0 then
			 PROG (concat (rev (!text)),!lineno,!lineno)
		    else (Add yytext; continue()) end
| 106 => let val yytext=yymktext() in Add yytext; YYBEGIN STRING; continue() end
| 109 => let val yytext=yymktext() in Add yytext; continue() end
| 11 => let val yytext=yymktext() in Add yytext; continue() end
| 111 => let val yytext=yymktext() in Add yytext; continue() end
| 114 => let val yytext=yymktext() in Add yytext; dec commentLevel;
		    if !commentLevel=0
			 then BOGUS_VALUE(!lineno,!lineno)
			 else continue()
		    end
| 117 => let val yytext=yymktext() in Add yytext; inc commentLevel; continue() end
| 120 => let val yytext=yymktext() in Add yytext; continue() end
| 122 => (continue())
| 125 => (dec commentLevel;
		          if !commentLevel=0 then YYBEGIN A else ();
			  continue ())
| 128 => (inc commentLevel; continue())
| 131 => (continue())
| 133 => let val yytext=yymktext() in Add yytext; YYBEGIN CODE; continue() end
| 135 => let val yytext=yymktext() in Add yytext; continue() end
| 14 => (YYBEGIN A; HEADER (concat (rev (!text)),!lineno,!lineno))
| 140 => let val yytext=yymktext() in Add yytext; error inputSource (!lineno) "unclosed string";
 	            inc lineno; YYBEGIN CODE; continue() end
| 143 => let val yytext=yymktext() in Add yytext; continue() end
| 146 => let val yytext=yymktext() in Add yytext; continue() end
| 152 => let val yytext=yymktext() in Add yytext; inc lineno; YYBEGIN F; continue() end
| 155 => let val yytext=yymktext() in Add yytext; YYBEGIN F; continue() end
| 158 => let val yytext=yymktext() in Add yytext; continue() end
| 160 => let val yytext=yymktext() in Add yytext; YYBEGIN STRING; continue() end
| 162 => let val yytext=yymktext() in Add yytext; error inputSource (!lineno) "unclosed string";
		    YYBEGIN CODE; continue() end
| 19 => let val yytext=yymktext() in Add yytext; inc lineno; continue() end
| 2 => let val yytext=yymktext() in Add yytext; YYBEGIN COMMENT; commentLevel := 1;
		    continue(); YYBEGIN INITIAL; continue() end
| 21 => let val yytext=yymktext() in Add yytext; continue() end
| 26 => (inc lineno; continue ())
| 31 => (continue())
| 34 => (OF(!lineno,!lineno))
| 38 => (FOR(!lineno,!lineno))
| 40 => (LBRACE(!lineno,!lineno))
| 42 => (RBRACE(!lineno,!lineno))
| 44 => (COMMA(!lineno,!lineno))
| 46 => (ASTERISK(!lineno,!lineno))
| 49 => (ARROW(!lineno,!lineno))
| 5 => (YYBEGIN EMPTYCOMMENT; commentLevel := 1; continue())
| 55 => (PREC(Header.LEFT,!lineno,!lineno))
| 62 => (PREC(Header.RIGHT,!lineno,!lineno))
| 72 => (PREC(Header.NONASSOC,!lineno,!lineno))
| 76 => let val yytext=yymktext() in lookup(yytext,!lineno,!lineno) end
| 79 => let val yytext=yymktext() in TYVAR(yytext,!lineno,!lineno) end
| 8 => let val yytext=yymktext() in Add yytext; YYBEGIN COMMENT; commentLevel := 1;
		    continue(); YYBEGIN CODE; continue() end
| 83 => let val yytext=yymktext() in IDDOT(yytext,!lineno,!lineno) end
| 86 => let val yytext=yymktext() in INT (yytext,!lineno,!lineno) end
| 89 => (DELIMITER(!lineno,!lineno))
| 91 => (COLON(!lineno,!lineno))
| 93 => (BAR(!lineno,!lineno))
| 96 => let val yytext=yymktext() in ID ((yytext,!lineno),!lineno,!lineno) end
| 98 => (pcount := 1; actionstart := (!lineno);
		    text := nil; YYBEGIN CODE; continue() before YYBEGIN A)
| _ => raise Internal.LexerError

		) end )

	val {fin,trans} = Vector.sub(Internal.tab, s)
	val NewAcceptingLeaves = fin::AcceptingLeaves
	in if l = !yybl then
	     if trans = #trans(Vector.sub(Internal.tab,0))
	       then action(l,NewAcceptingLeaves
) else	    let val newchars= if !yydone then "" else yyinput 1024
	    in if (size newchars)=0
		  then (yydone := true;
		        if (l=i0) then UserDeclarations.eof yyarg
		                  else action(l,NewAcceptingLeaves))
		  else (if i0=l then yyb := newchars
		     else yyb := substring(!yyb,i0,l-i0)^newchars;
		     yygone := !yygone+i0;
		     yybl := size (!yyb);
		     scan (s,AcceptingLeaves,l-i0,0))
	    end
	  else let val NewChar = Char.ord(CharVector.sub(!yyb,l))
		val NewChar = if NewChar<128 then NewChar else 128
		val NewState = Char.ord(CharVector.sub(trans,NewChar))
		in if NewState=0 then action(l,NewAcceptingLeaves)
		else scan(NewState,NewAcceptingLeaves,l+1,i0)
	end
	end
(*
	val start= if substring(!yyb,!yybufpos-1,1)="\n"
then !yybegin+1 else !yybegin
*)
	in scan(!yybegin (* start *),nil,!yybufpos,!yybufpos)
    end
in continue end
  in lex
  end
end
