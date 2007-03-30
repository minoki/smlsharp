(**
 * 
 * @author YAMATODANI Kiyoshi
 * @version $Id: Main.sml,v 1.9 2007/01/26 09:33:15 kiyoshiy Exp $
 *)
functor Main(structure Printer : RESULT_PRINTER
             structure SessionMaker : SESSION_MAKER) =
struct

  (***************************************************************************)

  structure C = Control
  structure Driver =
  TestDriver(
              structure TestCaseRunner = TestCaseRunner(SessionMaker)
              structure Printer = Printer
            )

  (***************************************************************************)

  val libdir = Configuration.LibDirectory
  val minimumPreludePath = libdir ^ "/" ^ Configuration.MinimumPreludeFileName
  val PreludePath = libdir ^ "/" ^ Configuration.PreludeFileName
  val compiledPreludePath = libdir ^ "/" ^ Configuration.CompiledPreludeFileName

  val USAGE = "prelude expectedDirectory resultDirectory sourcePath1 ..."

  fun isSuffix (string, suffix) =
      let
        val stringlen = size string
        val suffixlen = size suffix
      in
        suffixlen <= stringlen
        andalso
        suffix = String.substring (string, stringlen - suffixlen, suffixlen)
      end

  fun main
          (_, prelude :: expectedDirectory :: resultDirectory :: sourcePaths) =
      (
print ("prelude = [" ^ prelude ^ "]\n");
        Control.switchTrace := false;
        C.setControlOptions "IML_" OS.Process.getEnv;
        VM.instTrace := false;
        VM.stateTrace := false;
        VM.heapTrace := false;
        Driver.runTests
        {
          prelude = if prelude = "" then compiledPreludePath else prelude,
          isCompiledPrelude = prelude = "" orelse isSuffix(prelude, "smc"),
          sourcePaths = sourcePaths,
          expectedDirectory = expectedDirectory,
          resultDirectory = resultDirectory
        };
        OS.Process.success
      )
    | main _ =
      (print USAGE; OS.Process.failure)

  (***************************************************************************)

end

structure TextMLMain = Main(structure Printer = TextResultPrinter
                            structure SessionMaker = SessionMaker_ML)
structure TextRemoteMain = Main(structure Printer = TextResultPrinter
                                structure SessionMaker = SessionMaker_Remote)
structure HTMLMLMain = Main(structure Printer = HTMLResultPrinter
                            structure SessionMaker = SessionMaker_ML)
structure HTMLRemoteMain = Main(structure Printer = HTMLResultPrinter
                                structure SessionMaker = SessionMaker_Remote)
