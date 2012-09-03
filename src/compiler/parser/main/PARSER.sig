(**
 * Parser of ML source code.
 *
 * @copyright (c) 2006, Tohoku University.
 * @author YAMATODANI Kiyoshi
 * @version $Id: PARSER.sig,v 1.7 2006/02/28 16:11:02 kiyoshiy Exp $
 *)
signature PARSER =
sig

  (***************************************************************************)

  (** parse context *)
  type context

  (***************************************************************************)

  (** raised when whole source code is parsed. *)
  exception EndOfParse

  (** parse error *)
  exception ParseError

  (***************************************************************************)

  (**
   * create fresh parse context.
   *)
  val createContext :
      {
        (** name of source *)
        sourceName : string,
        (** called when lex/parse error found. *)
        onError : string * Loc.pos * Loc.pos -> unit,
        (** this should return one line from source. *)
        getLine : int -> string
      }
      -> context

  val resumeContext : context -> context

  (** parse.
   * @params context
   * @param context parse context
   * @return parse result and new context. 
   *)
  val parse : context -> (Absyn.parseresult * context)

  val errorToString : string * Loc.pos * Loc.pos -> string

  (***************************************************************************)

end
