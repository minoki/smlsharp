(*
character constants
*)

val alert = (#"\a", "\a");
val backspace = (#"\b", "\b");
val horizontal_tab = (#"\t", "\t");
val newline = (#"\n", "\n");
val vertical_tab = (#"\v", "\v");
val form_feed = (#"\f", "\f");
val carriage_return = (#"\r", "\r");

(* The below is generated by the following code.
fun f num =
    let val encoded = Char.toString(Char.chr num)
    in
      "val ctrl"
      ^ (Int.toString num)
      ^ " = (#\"" ^ encoded ^ "\", \"" ^ encoded ^ "\");\n"
    end;
List.tabulate (32, fn num => print (f num));
*)
val ctrl0 = (#"\^@", "\^@");
val ctrl1 = (#"\^A", "\^A");
val ctrl2 = (#"\^B", "\^B");
val ctrl3 = (#"\^C", "\^C");
val ctrl4 = (#"\^D", "\^D");
val ctrl5 = (#"\^E", "\^E");
val ctrl6 = (#"\^F", "\^F");
val ctrl7 = (#"\^G", "\^G");
val ctrl8 = (#"\^H", "\^H");
val ctrl9 = (#"\^I", "\^I");
val ctrl10 = (#"\^J", "\^J");
val ctrl11 = (#"\^K", "\^K");
val ctrl12 = (#"\^L", "\^L");
val ctrl13 = (#"\^M", "\^M");
val ctrl14 = (#"\^N", "\^N");
val ctrl15 = (#"\^O", "\^O");
val ctrl16 = (#"\^P", "\^P");
val ctrl17 = (#"\^Q", "\^Q");
val ctrl18 = (#"\^R", "\^R");
val ctrl19 = (#"\^S", "\^S");
val ctrl20 = (#"\^T", "\^T");
val ctrl21 = (#"\^U", "\^U");
val ctrl22 = (#"\^V", "\^V");
val ctrl23 = (#"\^W", "\^W");
val ctrl24 = (#"\^X", "\^X");
val ctrl25 = (#"\^Y", "\^Y");
val ctrl26 = (#"\^Z", "\^Z");
val ctrl27 = (#"\^[", "\^[");
val ctrl28 = (#"\^\", "\^\");
val ctrl29 = (#"\^]", "\^]");
val ctrl30 = (#"\^^", "\^^");
val ctrl31 = (#"\^_", "\^_");

val dec000 = (#"\000", "\000") = (#"\^@", "\^@");
val dec032 = (#"\032", "\032") = (#" ", " ");
val dec064 = (#"\064", "\064") = (#"@", "@");
val dec096 = (#"\096", "\096") = (#"`", "`");

val hex0000 = (#"\u0000", "\u0000") = (#"\^@", "\^@");
val hex0020 = (#"\u0020", "\u0020") = (#" ", " ");
val hex0040 = (#"\u0040", "\u0040") = (#"@", "@");
val hex0060 = (#"\u0060", "\u0060") = (#"`", "`");
val hex00FF = (#"\u00FF", "\u00FF") = (#"\255", "\255");

val doubleQuote = (#"\"", "\"") = (#"\034", "\034");
val backSlash = (#"\\", "\\") = (#"\092", "\092");
val multiBySpace = "abc\ \def" = "abcdef";
val multiByTab = "abc\	\def" = "abcdef";
val multiByNewline = "abc\
                     \def" = "abcdef";
val multiByFormfeed = "abc\\def" = "abcdef";
