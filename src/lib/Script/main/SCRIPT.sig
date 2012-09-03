(**
 * @author YAMATODANI Kiyoshi
 * @copyright (c) 2006, Tohoku University.
 * @version $Id: SCRIPT.sig,v 1.8 2006/03/02 16:20:35 kiyoshiy Exp $
 *)
signature SCRIPT =
sig

  (***************************************************************************)
  (* Process *)

(*
  not implemented.
  (**
   * replace the current process image with a new process image.
   *)
  val exec : (string * string list) -> 'a
*)

  (**
   * issue a shell command.
   * @params (command, args)
   * @param command command name
   * @param args arguments passed to the command.
   * @return exit status of the command.
   *)
  val system : (string * string list) -> OS.Process.status

  (**
   * exits the current process.
   * This is a shorthand of <code>OS.Process.exit</code>.
   * @params status
   * @param status exit code.
   * @return This function does not return if success.
   *)
  val exit : OS.Process.status -> 'a

  (**
   * suspends execution of the current process.
   * This is a shorthand of <code>OS.Process.sleep o Time.fromSeconds</code>.
   * @params seconds
   * @param seconds the number of seconds for which to suspend execution.
   *)
  val sleep : int -> unit

  (**
   * get the value for environment name.
   * <pre>
   * -&gt;env "OS";
   * val it = "Windows_NT" : string
   * -&gt;env "FOO";
   * val it = "" : string
   * </pre>
   * @params name
   * @param name name of the environment
   * @return the string of the name. An zero-length string is returned if the
   *        name is not defined.
   *)
  val env : string -> string

  (**
   * command line arguments.
   *)
  val argv : string list

  (**
   * change working directory.
   * <pre>
   * -&gt;cd "D:/home";
   * val it = () : unit
   * -&gt;cd "/usr/";
   * val it = () : unit
   * </pre>
   * @params path
   * @param path the path of directory to become new working directory.
   * @throws SysErr if the specified path does not point a valid directory.
   *)
  val cd : string -> unit

  (**
   * get the current working directory.
   * <pre>
   * -&gt;pwd ();
   * val it = "/usr" : string
   * </pre>
   * @return the current working directory
   *)
  val pwd : unit -> string

  (****************************************)
  (* IO *)

  (** stream of a file. *)
  datatype file =
           (** input stream *) Instream of TextIO.instream
         | (** output stream *) Outstream of TextIO.outstream

  (** standard input *)
  val stdIn : file

  (** standard output *)
  val stdOut : file

  (** standard error *)
  val stdErr : file

  (**
   * create a stream of the file.
   * @params fileName mode
   * @param fileName name of the file to open
   * @param mode "r" for read mode, "w" for write mode, "a" for append mode.
   * @return a stream of the opened file.
   *)
  val fopen : string -> string -> file

  (**
   * close a file stream.
   * @params file
   * @param file the stream to close
   *)
  val fclose : file -> unit

  (**
   * indicates whether the file stream reaches at the EOF.
   * @params file
   * @param file the stream
   * @return true if the stream has reached the end of file.
   *)
  val feof : file -> bool

  (**
   * emits the contents remaining in buffer into the file stream.
   * @params file
   * @param file the stream
   *)
  val fflush : file -> unit

  (**
   * gets the character at the top of the file stream.
   * The character is left at the stream.
   * @params file
   * @param file the stream
   * @return the character at the top of the stream. NONE is returned if the
   *        stream is at the end of file.
   *)
  val fpeek : file -> char option

  (**
   * get a line from the stream.
   * If ls is NONE, get the all contents from the stream.
   * If ls is SOME "", a sequence of consecutive newline characters is
   * considered as line separator.
   * If ls is SOME ls', ls' is considered as line separator.
   * @params stream ls
   * @param stream an input stream
   * @param ls line separator
   * @return a string followed by a ls in the stream.
   *)
  val fgets : file -> string option -> string

  (**
   * readline is similar with gets, except that readline raises EOF when EOF
   * is encountered.
   * @params stream ls
   * @param stream an input stream
   * @param ls line separator
   * @return a line
   * @throws EOF if the stream is already at the end of file.
   *)
  val readline : file -> string option -> string

  (**
   * get all contents of file.
   * @params stream ls
   * @param stream an input stream
   * @param ls line separator
   * @return lines 
   *)
  val readlines : file -> string option -> string list

  (**
   * puts a character to an output stream.
   * @params file char
   * @param file the stream
   * @param char a character which is put on the stream.
   *)
  val fputc : file -> char -> unit

  (**
   * puts a string to an output stream.
   * A newline is appended unless the string ends with a newline.
   * @params file string
   * @param file the stream
   * @param string a string which is put on the stream.
   *)
  val fputs : file -> string -> unit

  (****************************************)
  (* Text *)

  (** regular expression *)
  type pattern = string

  (**
   * truncate the last character from the string.
   * If the string is zero-length, a zero-length string is returned.
   * If the string ends with a two characters sequence "\r\n", these two
   * characters are stripped.
   * <pre>
   * -&gt;chop "abc\r\n";
   * val it = "abc" : string
   * -&gt;chop "abc\n\r";
   * val it = "abc\n" : string
   * -&gt;chop "abc\n";
   * val it = "abc" : string
   * -&gt;chop "abc\r";
   * val it = "abc" : string
   * -&gt;chop "abc";
   * val it = "ab" : string
   * -&gt;chop "";
   * val it = "" : string
   * </pre>
   *)
  val chop : string -> string

  (**
   * converts the integer to its string representation.
   * <pre>
   * -&gt;itoa 123;
   * val it = "123" : string
   * </pre>
   * @params num
   * @param num an integer
   * @return a string converted from the integer.
   *)
  val itoa : int -> string

  (**
   * converts the initial portion of the string to its int representation.
   * If the string does not begin with a numeral text, it returns 0.
   * <pre>
   * -&gt;atoi "123xyz";
   * val it = 123 : int
   * </pre>
   * @params string
   * @param string a string
   * @return an integer converted from the string.
   *)
  val atoi : string -> int

  (**
   * if the pattern matches with a substring of the string, returns true.
   * <pre>
   * -&gt;"xyzabcxyz" =~ "ab*c";
   * val it = true : bool
   * </pre>
   * @params (string, pattern)
   * @param string a string.
   * @param pattern a regular expression.
   *)
  val =~ : string * pattern -> bool

  (**
   * get location of the left most occurrence of a sub string which
   * matches with the pattern.
   * <pre>
   * -&gt;find "ab*c" "xyzacxyz";
   * val it = SOME (3, 2) : (int * int) option
   * -&gt;find "ab+c" "xyzacxyz";
   * val it = NONE : (int * int) option
   * </pre>
   * @params pattern string
   * @param pattern a regular expression
   * @param string the string
   * @return option of a pair of the index and the length of matched substring.
   *)
  val find : pattern -> string -> (int * int) option

  (**
   * get locations of occurrences of sub strings which match with the pattern.
   * @params pattern string
   * @param pattern a regular expression
   * @param string the string
   * @return a list of pairs of the index and the length of matched
   *       sub-strings.
   *)
  val global_find : pattern -> string -> (int * int) list

  (**
   * 
   *)
  val find_group : pattern -> string -> (int * int) option list option

  val global_find_group : pattern -> string -> (int * int) option list list

  (**
   * get the left most substring of the string which matches with the pattern.
   * If any matched substring is not found, a zero-length string is returned.
   * <pre>
   * -&gt; slice "ab*c" "xyzabbcxyzabcxyz"
   * val it = "abbc" : string
   * </pre>
   * @params pattern string
   * @param pattern a regular expression
   * @param string the string
   * @return a substring which matches with the pattern.
   *)
  val slice : pattern -> string -> string

  (**
   * get substrings of the string which match with the pattern.
   * @params pattern string
   * @param pattern a regular expression
   * @param string the string
   * @return a list of substrings which match with the pattern.
   *)
  val global_slice : pattern -> string -> string list

  val slice_group : pattern -> string -> string list option

  val global_slice_group : pattern -> string -> string list list

  (**
   * substitute patterns in the string with replace.
   * <pre>
   * -&gt;subst "ab*c" "ABC" "xyzabbcxyzabcxyz"
   * val it = "xyzABCxyzabcxyz" : string
   * </pre>
   * @params pattern replace string
   * @param pattern the pattern
   * @param replace a string with which the matched substring is replaced.
   * @param string the string
   *)
  val subst : pattern -> string -> string -> string

  (**
   * <pre>
   * -&gt;global_subst "ab*c" "ABC" "xyzabbcxyzabcxyz"
   * val it = "xyzABCxyzABCxyz" : string
   * </pre>
   *)
  val global_subst : pattern -> string -> string -> string

  (**
   * @params pattern replacer string
   * @param pattern a regular expression pattern
   * @param replacer a function which takes mathced strings and returns new
   *              string with which the matched string is replaced.
   * @param string the string with which the pattern is matched.
   * @return new string in which the left most matched sub string is replaced
   *       with a new string which the replacer returns.
   *)
  val replace : pattern -> (string list -> string) -> string -> string

  val global_replace : pattern -> (string list -> string) -> string -> string

  (**
   *  get a list of substrings which are delimited by a substring which matches
   * with the pattern.
   * <pre>
   * -&gt;fields "ab*c" "abcacxyzabcabbcXYZac"
   * val it = ["","","xyz","","XYZ",""] : string list
   * </pre>
   *)
  val fields : pattern -> string -> string list

  (**
   *  get a list of substrings which are delimited by consecutive substrings
   * which match with the pattern.
   * <pre>
   * -&gt;tokens "ab*c" "abcacxyzabcabbcXYZac"
   * val it = ["xyz","XYZ"] : string list
   * </pre>
   * <code>tokens p s</code> is equivalent with
   * <pre>
   * List.map (fn s => s &lt;&gt; "") (fields p s)
   * </pre>
   *)
  val tokens : pattern -> string -> string list

  (***************************************************************************)

end
