(**
 * @copyright (c) 2006, Tohoku University.
 *)

functor UIntFun(W : WORD) : WORD = 
struct
  open W
  val toString = (fn string => "0x" ^ string) o W.toString
end;
structure UInt8 = UIntFun(Word8);
structure SInt8 = Int;
structure UInt16 = UIntFun(Word);
structure SInt16 = Int;
structure UInt24 = UIntFun(Word);
structure SInt24 = Int;
structure UInt32 = UIntFun(Word32);
structure SInt32 = Int32;
structure Real64 = Real64;

(**
 * This structure declares basic types
 *)
structure BasicTypes = 
struct

  (***************************************************************************)

  (** unsigned 8 bit integer *)
  type UInt8 = Word8.word;

  (** signed 8 bit integer *)
  type SInt8 = Int.int; (* use Int8 if available. *)

  (** unsigned 16 bit integer *)
  type UInt16 = Word.word (* use Word16 if available. *)

  (** signed 16 bit integer *)
  type SInt16 = Int.int; (* use Int16 if available. *)

  (** unsigned 24 bit integer *)
  type UInt24 = Word.word;

  (** signed 24 bit integer *)
  type SInt24 = Int.int;

  (** unsigned 32 bit integer *)
  type UInt32 = Word32.word;

  (** signed 32 bit integer *)
  type SInt32 = Int32.int;

  (** 64 bit real *)
  type Real64 = Real64.real;

  (***************************************************************************)

  val BytesOfUInt32 = 0w4 : UInt32
  val WordsOfReal64 = 0w2 : UInt32

  (***************************************************************************)

  (* SInt <-> SInt *)
  fun SInt32ToSInt8 (sint32 : SInt32) = (SInt8.fromLarge sint32) : SInt8
  fun SInt32ToSInt16 (sint32 : SInt32) = (SInt16.fromLarge sint32) : SInt16
  fun SInt32ToSInt24 (sint32 : SInt32) = (SInt24.fromLarge sint32) : SInt24

  fun SInt8ToSInt32 (sint8 : SInt8) = (SInt8.toLarge sint8) : SInt32
  fun SInt16ToSInt32 (sint16 : SInt16) = (SInt16.toLarge sint16) : SInt32
  fun SInt24ToSInt32 (sint24 : SInt24) = (SInt24.toLarge sint24) : SInt32

  (* UInt <-> UInt *)
  fun UInt32ToUInt8 (uint32 : UInt32) = (UInt8.fromLargeWord uint32) : UInt8
  fun UInt32ToUInt16 (uint32 : UInt32) = (UInt16.fromLargeWord uint32) : UInt16
  fun UInt32ToUInt24 (uint32 : UInt32) = (UInt24.fromLargeWord uint32) : UInt24

  fun UInt8ToUInt32 (uint8 : UInt8) = (UInt8.toLargeWord uint8) : UInt32
  fun UInt16ToUInt32 (uint16 : UInt16) = (UInt16.toLargeWord uint16) : UInt32
  fun UInt24ToUInt32 (uint24 : UInt24) = (UInt24.toLargeWord uint24) : UInt32

  (* UInt <-> SInt *)
  fun SInt8ToUInt32 (sint8 : SInt8) = (UInt32.fromInt sint8) : UInt32
  fun SInt16ToUInt32 (sint16 : SInt16) = (UInt32.fromInt sint16) : UInt32
  fun SInt24ToUInt32 (sint24 : SInt24) = (UInt32.fromInt sint24) : UInt32
  fun SInt32ToUInt32 (sint32 : SInt32) = (UInt32.fromLargeInt sint32) : UInt32

  fun UInt8ToSInt32 (uint8 : UInt8) = (UInt8.toLargeIntX uint8) : SInt32
  fun UInt16ToSInt32 (uint16 : UInt16) = (UInt16.toLargeIntX uint16) : SInt32
  fun UInt24ToSInt32 (uint24 : UInt24) = (UInt24.toLargeIntX uint24) : SInt32
  fun UInt32ToSInt32 (uint32 : UInt32) = (UInt32.toLargeIntX uint32) : SInt32

  (* Int <-> SInt *)
  fun IntToSInt8 (int : int) = int : SInt8
  fun IntToSInt16 (int : int) = int : SInt16
  fun IntToSInt24 (int : int) = int : SInt24
  fun IntToSInt32 (int : int) = (Int.toLarge int) : SInt32

  fun SInt8ToInt (sint8 : SInt8) = SInt8.toInt sint8
  fun SInt16ToInt (sint16 : SInt16) = SInt16.toInt sint16
  fun SInt24ToInt (sint24 : SInt24) = SInt24.toInt sint24
  fun SInt32ToInt (sint32 : SInt32) = SInt32.toInt sint32 : int

  (* Int <-> UInt *)
  fun IntToUInt8 (int : int) = UInt8.fromInt int
  fun IntToUInt16 (int : int) = UInt16.fromInt int
  fun IntToUInt24 (int : int) = UInt24.fromInt int
  fun IntToUInt32 (int : int) = UInt32.fromInt int

  fun UInt8ToInt (uint8 : UInt8) = UInt8.toInt uint8
  fun UInt16ToInt (uint16 : UInt16) = UInt16.toInt uint16
  fun UInt24ToInt (uint24 : UInt24) = UInt24.toInt uint24
  fun UInt32ToInt (uint32 : UInt32) = UInt32.toInt uint32

  (* Word <-> UInt *)
  fun WordToUInt8 (word : word) = ((UInt8.fromInt o Word.toInt) word) : UInt8
  fun WordToUInt16 (word : word) = word : UInt16
  fun WordToUInt24 (word : word) = word : UInt24
  fun WordToUInt32 (word : word) = (Word.toLargeWord word) : UInt32

  fun UInt8ToWord (uint8 : UInt8) = ((Word.fromInt o UInt8.toInt) uint8) : word
  fun UInt16ToWord (uint16 : UInt16) = uint16 : word
  fun UInt24ToWord (uint24 : UInt24) = uint24 : word
  fun UInt32ToWord (uint32 : UInt32) = (Word.fromLargeWord uint32) : word

  (* Word <-> SInt *)
  fun WordToSInt8 (word : word) = (Word.toInt word) : SInt8
  fun WordToSInt16 (word : word) = (Word.toInt word) : SInt16
  fun WordToSInt24 (word : word) = (Word.toInt word) : SInt24
  fun WordToSInt32 (word : word) = (Word.toLargeInt word) : SInt32

  fun SInt8ToWord (sint8 : SInt8) = Word.fromInt sint8
  fun SInt16ToWord (sint16 : SInt16) = Word.fromInt sint16
  fun SInt24ToWord (sint24 : SInt24) = Word.fromInt sint24
  fun SInt32ToWord (sint32 : SInt32) = Word.fromLargeInt sint32

  (* Real <-> Real64 *)
  fun RealToReal64 (real : real) = (Real.toLarge real) : Real64
  fun Real64ToReal (real : Real64) =
      (Real.fromLarge IEEEReal.TO_NEAREST real) : real
  fun Real64ToSInt32 (real : Real64) =
      Real64.toLargeInt (IEEEReal.getRoundingMode ()) real
  fun SInt32ToReal64 (sint32 : SInt32) = Real64.fromLargeInt sint32

  fun StringLengthToPaddedUInt8ListLength stringLength =
      (stringLength + 4) div 4

  fun StringToPaddedUInt8ListLength string =
      StringLengthToPaddedUInt8ListLength (String.size string)

  (* translates a string to a list of UInt8 *)
  fun StringToPaddedUInt8List string =
      let
        val length = String.size string
        val padding =
            case length mod 4 of
              0 => "\000\000\000\000"
            | 1 => "\000\000\000"
            | 2 => "\000\000"
            | 3 => "\000"
            | _ =>
              raise Fail "length mod 4 should be between 0 and 3."
      in
        map
            (IntToUInt8 o Char.ord)
            (String.explode (string ^ padding))
      end

  fun UInt8ListToString bytes =
      let
        val chars = map (Char.chr o UInt8.toInt) bytes
      in implode chars end

  fun StringToUInt8Array string =
      let
        val length = String.size string
        val array = Word8Array.array (length, 0w0)
        val _ =
            foldl
            (fn (char, index) =>
                (
                  Word8Array.update
                      (array, index, UInt8.fromInt(Char.ord(char)));
                  index + 1)
                )
                0
                (explode string)
      in (array, IntToUInt32 length) end

  fun UInt8ArrayToString (array, length) =
      let
        val bytes =
            Word8Array.foldri
                (fn (_, byte, bytes) => byte :: bytes)
                []
                (array, 0, SOME (UInt32ToInt length))
        val chars = map (Char.chr o UInt8.toInt) bytes
      in implode chars end

  (***************************************************************************)

end

