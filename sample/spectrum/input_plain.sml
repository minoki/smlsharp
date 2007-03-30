(**
 * input_plain.sml
 *
 * @copyright (c) 2006-2007, Tohoku University.
 * @author UENO Katsuhiro
 * @version $Id: input_plain.sml,v 1.1.2.1 2007/03/26 06:26:50 katsu Exp $
 *)

functor Input(
  val numSamples : int
) :> INPUT =
struct

  type input =
       Libc.c_file * bool ref
       
  fun openInput () =
      let
        val c_file = Libc.fdopen (0, "rb")
      in
        if c_file = NULL then raise Fail "fdopen" else ();
        (c_file, ref false)
      end

  fun startInput (_:input) = ()
        
  fun closeInput ((c_file, _):input) =
      Libc.fclose c_file

  fun fill ((c_file, eof):input) = false

  val buffer = Array.array (numSamples, 0w0)

  fun read ((c_file, eof):input) =
      let
        val n = if !eof
                then 0
                else Libc.fread (buffer, numSamples, c_file)
      in
        if n < numSamples
        then Array.modifyi (fn (i,x) => if i < n then x else 0w0) buffer
        else ();
        eof := n < numSamples
      end

  fun finished ((c_file, eof):input) = !eof

end
