(**
 * x86 RTL
 * @copyright (c) 2009, Tohoku University.
 * @author UENO Katsuhiro
 * @version $Id: $
 *)

structure RTLUtils :> sig

  structure Var : sig
    type set
    type defuseSet = {defs: set, uses: set}
    val format_set : set SMLFormat.BasicFormatters.formatter
    val setUnion : set * set -> set
    val setMinus : set * set -> set
    val setIsSubset : set * set -> bool
    val emptySet : set
    val fold : (RTL.var * 'a -> 'a) -> 'a -> set -> 'a
    val filter : (RTL.var -> bool) -> set -> set
    val inDomain : set * RTL.id -> bool
    val find : set * RTL.id -> RTL.var option
    val isEmpty : set -> bool
    val fromList : RTL.var list -> set
    val singleton : RTL.var -> set
    val defuseFirst : RTL.first -> defuseSet
    val defuseInsn : RTL.instruction -> defuseSet
    val defuseLast : RTL.last -> defuseSet
    val defuse : RTLEdit.node -> defuseSet
    val clobsFirst : RTL.first -> set
    val clobsInsn : RTL.instruction -> set
    val clobsLast : RTL.last -> set
    val clobs : RTLEdit.node -> set
  end

  structure Slot : sig
    type set
    type defuseSet = {defs: set, uses: set}
    val format_set : set SMLFormat.BasicFormatters.formatter
    val setUnion : set * set -> set
    val setMinus : set * set -> set
    val setIsSubset : set * set -> bool
    val emptySet : set
    val fold : (RTL.slot * 'a -> 'a) -> 'a -> set -> 'a
    val filter : (RTL.slot -> bool) -> set -> set
    val inDomain : set * RTL.id -> bool
    val find : set * RTL.id -> RTL.slot option
    val isEmpty : set -> bool
    val fromList : RTL.slot list -> set
    val singleton : RTL.slot -> set
    val defuseFirst : RTL.first -> defuseSet
    val defuseInsn : RTL.instruction -> defuseSet
    val defuseLast : RTL.last -> defuseSet
    val defuse : RTLEdit.node -> defuseSet
  end

  val labelPtrTy : RTL.labelReference -> RTL.ptrTy
  val labelTy : RTL.labelReference -> RTL.ty
  val constTy : RTL.const -> RTL.ty
  val addrTy : RTL.addr -> RTL.ptrTy
  val dstTy : RTL.dst -> RTL.ty
  val operandTy : RTL.operand -> RTL.ty

  val handlerLabels : RTL.handler -> RTL.label list
  (* nil means exit *)
  val successors : RTL.last -> RTL.label list

  val edges : RTL.graph
              -> {succs: RTL.label list, preds: RTL.label list}
                 RTLEdit.annotatedGraph
  val preorder : RTL.graph -> RTL.label list
  val postorder : RTL.graph -> RTL.label list

  type 'a analysis =
      {
        init: 'a,
        join: 'a * 'a -> 'a,
        pass: RTLEdit.node * 'a -> 'a,
        filterIn: RTL.label * 'a -> 'a,
        filterOut: RTL.label * 'a -> 'a,
        changed: {old:'a, new:'a} -> bool
      }

  type 'a answer =
      {
        answerIn: 'a,
        answerOut: 'a,
        succs: RTL.label list,
        preds: RTL.label list
      }

  val format_answer : 'a SMLFormat.BasicFormatters.formatter
                      -> 'a answer SMLFormat.BasicFormatters.formatter

  val analyzeFlowBackward :
      'a analysis -> RTL.graph -> 'a answer RTLEdit.annotatedGraph
  val analyzeFlowForward :
      'a analysis -> RTL.graph -> 'a answer RTLEdit.annotatedGraph



(*
  val edges : RTL.graph
              -> {edges: {succs: RTL.label list,
                          preds: RTL.label list} RTL.LabelMap.map,
                  exits: RTL.label list}

  type 'a analysis =
      {
        init: 'a,
        join: 'a * 'a -> 'a,
        pass: RTLEdit.node * 'a -> 'a,
        changed: {old:'a, new:'a} -> bool
      }

  type 'a answer =
      {answerIn: 'a, answerOut: 'a} RTL.LabelMap.map

  val analyzeFlowBackward : 'a analysis -> RTL.graph -> 'a answer
  val analyzeFlowForward : 'a analysis -> RTL.graph -> 'a answer
*)

end =
struct
fun puts s = print (s ^ "\n")
fun putfs s = print (Control.prettyPrint s ^ "\n")

  structure I = RTL
  open RTL

  infix ++

  type 'a set = 'a LocalVarID.Map.map
  type 'a defuseSet = {defs: 'a set, uses: 'a set}
  val emptySet = LocalVarID.Map.empty : 'a set

  local
    open SMLFormat.BasicFormatters
  in
  fun format_set fmt set =
      format_string "{" @
      format_list
        (fn (x,y) => LocalVarID.format_id x @ format_string ":" @ fmt y,
         format_string ",")
        (LocalVarID.Map.listItemsi set) @
      format_string "}"
  end

  fun setUnion (set1:''a set, set2:''a set) : ''a set =
      LocalVarID.Map.unionWith
        (fn (x,y) => if x = y then x else raise Control.Bug "union")
        (set1, set2)

  fun setMinus (set1:'a set, set2:'a set) : 'a set =
      LocalVarID.Map.filteri
        (fn (id, _) => not (LocalVarID.Map.inDomain (set2, id)))
        set1
(*
      LocalVarID.Map.foldli
        (fn (id, v, set) =>
            case LocalVarID.Map.find (set2, id) of
              NONE => LocalVarID.Map.insert (set, id, v)
            | SOME _ => set)
        LocalVarID.Map.empty
        set1
*)

  fun setIsSubset (set1:'a set, set2:'a set) =
      LocalVarID.Map.foldli
        (fn (id, _, b) => b andalso LocalVarID.Map.inDomain (set2, id))
        true
        set1

  fun singleton f (v:'a) =
      LocalVarID.Map.singleton (f v, v) : 'a set

  fun varSet vars =
      foldl (fn (var as {id,...}:I.var, set) =>
                LocalVarID.Map.insert (set, id, var))
            emptySet vars

  fun slotSet slots =
      foldl (fn (slot as {id,...}:I.slot, set) =>
                LocalVarID.Map.insert (set, id, slot))
            emptySet slots

  fun ({defs=d1, uses=u1}:''a defuseSet) ++ ({defs=d2, uses=u2}:''a defuseSet) =
      {defs = setUnion (d1, d2), uses = setUnion (u1, u2)} : ''a defuseSet

  val duEmpty =
      {defs = emptySet, uses = emptySet} : 'a defuseSet
  fun useSet set =
      {defs = emptySet, uses = set} : 'a defuseSet
  fun defSet set =
      {defs = set, uses = emptySet} : 'a defuseSet
  fun useAll ({defs, uses}:''a defuseSet) =
      {defs = emptySet, uses = setUnion (defs, uses)} : ''a defuseSet

  fun duAddr varSet addr =
      case addr of
        I.ADDRCAST (_, addr) => duAddr varSet addr
      | I.ABSADDR _ => duEmpty
      | I.DISP (const, addr) => duAddr varSet addr
      | I.BASE var => useSet (varSet [var])
      | I.ABSINDEX {base, scale, index} => useSet (varSet [index])
      | I.BASEINDEX {base, scale, index} => (useSet (varSet [base, index]))
      | I.POSTFRAME {offset, size} => duEmpty
      | I.PREFRAME {offset, size} => duEmpty
      | I.WORKFRAME slot => duEmpty
      | I.FRAMEINFO offset => duEmpty

  fun duMem varSet (I.ADDR addr) = duAddr varSet addr
    | duMem varSet (I.SLOT _) = duEmpty

  fun duDstVar (I.REG var) = defSet (singleton #id var)
    | duDstVar (I.COUPLE (_, {hi,lo})) = duDstVar hi ++ duDstVar lo
    | duDstVar (I.MEM (_, mem)) = duMem varSet mem

  fun duDstSlot (I.REG var) = duEmpty
    | duDstSlot (I.COUPLE (_, {hi,lo})) = duDstSlot hi ++ duDstSlot lo
    | duDstSlot (I.MEM (_, I.SLOT slot)) = defSet (singleton #id slot)
    | duDstSlot (I.MEM (_, I.ADDR addr)) = duEmpty

  fun duOp duDst (I.CONST _) = duEmpty
    | duOp duDst (I.REF (_, dst)) = useAll (duDst dst)

(*
  fun duTest duDst insn =
      case insn of
        I.TEST_SUB (_, op1, op2) => duOp duDst op1 ++ duOp duDst op2
      | I.TEST_AND (_, op1, op2) => duOp duDst op1 ++ duOp duDst op2
        val duTest = duTest duDst
*)

  fun defuseInsn (func as {varSet, slotSet, duDst}) insn =
      let
        val duOp = duOp duDst
        val duAddr = duAddr varSet
      in
        case insn of
          I.NOP => duEmpty
        | I.STABILIZE => duEmpty
        | I.REQUEST_SLOT slot => defSet (slotSet [slot])
        | I.REQUIRE_SLOT slot => useSet (slotSet [slot])
        | I.USE ops => foldr (fn (x,z) => duOp x ++ z) duEmpty ops
        | I.COMPUTE_FRAME {uses, clobs} =>
          useSet (varSet (LocalVarID.Map.listItems uses))
        | I.MOVE (ty, dst, op1) => duDst dst ++ duOp op1
        | I.MOVEADDR (ty, dst, addr) => duDst dst ++ duAddr addr
        | I.COPY {ty, dst:I.dst, src:I.operand, clobs} => duDst dst ++ duOp src
        | I.MLOAD {ty, dst:I.slot, srcAddr, size, defs, clobs} =>
          defSet (slotSet [dst]) ++ defSet (varSet defs)
          ++ duAddr srcAddr ++ duOp size
        | I.MSTORE {ty, dstAddr, src:I.slot, size, defs, clobs, global} =>
          useSet (slotSet [src]) ++ defSet (varSet defs)
          ++ duAddr dstAddr ++ duOp size
        | I.EXT8TO32 (_, dst, op1) => duDst dst ++ duOp op1
        | I.EXT16TO32 (_, dst, op1) => duDst dst ++ duOp op1
        | I.EXT32TO64 (_, dst, op1) => duDst dst ++ duOp op1
        | I.DOWN32TO8 (_, dst, op1) => duDst dst ++ duOp op1
        | I.DOWN32TO16 (_, dst, op1) => duDst dst ++ duOp op1
        | I.ADD (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.SUB (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.MUL ((_,dst), (_,op1), (_,op2)) => duDst dst ++ duOp op1 ++ duOp op2
        | I.DIVMOD ({div=(_,ddiv), mod=(_,dmod)}, (_,op1), (_,op2)) =>
          duDst ddiv ++ duDst dmod ++ duOp op1 ++ duOp op2
        | I.AND (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.OR (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.XOR (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.LSHIFT (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.RSHIFT (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.ARSHIFT (ty, dst, op1, op2) => duDst dst ++ duOp op1 ++ duOp op2
        | I.TEST_SUB (_, op1, op2) => duOp op1 ++ duOp op2
        | I.TEST_AND (_, op1, op2) => duOp op1 ++ duOp op2
        | I.TEST_LABEL (_, op1, l) => duOp op1
        | I.NOT (ty, dst, op1) => duDst dst ++ duOp op1
        | I.NEG (ty, dst, op1) => duDst dst ++ duOp op1
        | I.SET (cc1, ty, dst, {test}) =>
          duDst dst ++ defuseInsn func test
        | I.LOAD_FP dst => duDst dst
        | I.LOAD_SP dst => duDst dst
        | I.LOAD_PREV_FP dst => duDst dst
        | I.LOAD_RETADDR dst => duDst dst
(*
        | I.SAVE_FP op1 => duOp op1
        | I.SAVE_SP op1 => duOp op1
*)
        | I.LOADABSADDR {ty, dst, symbol, thunk} => duDst dst
        | I.X86 (I.X86LEAINT (ty, dst, {base, shift, offset, disp})) =>
          duDst dst ++ useSet (varSet [base, offset])
(*
        | I.X86 (I.X86HI8OF16 (_, dst, op1)) => duDst dst ++ duOp op1
*)
        | I.X86 (I.X86FLD (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FLD_ST st) => duEmpty
        | I.X86 (I.X86FST (ty, mem)) => duDst (I.MEM (ty, mem))
        | I.X86 (I.X86FSTP (ty, mem)) => duDst (I.MEM (ty, mem))
        | I.X86 (I.X86FSTP_ST st) => duEmpty
        | I.X86 (I.X86FADD (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FADD_ST (st1, st2)) => duEmpty
        | I.X86 (I.X86FADDP st1) => duEmpty
        | I.X86 (I.X86FSUB (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FSUB_ST (st1, st2)) => duEmpty
        | I.X86 (I.X86FSUBP st1) => duEmpty
        | I.X86 (I.X86FSUBR (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FSUBR_ST (st1, st2)) => duEmpty
        | I.X86 (I.X86FSUBRP st1) => duEmpty
        | I.X86 (I.X86FMUL (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FMUL_ST (st1, st2)) => duEmpty
        | I.X86 (I.X86FMULP st1) => duEmpty
        | I.X86 (I.X86FDIV (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FDIV_ST (st1, st2)) => duEmpty
        | I.X86 (I.X86FDIVP st1) => duEmpty
        | I.X86 (I.X86FDIVR (ty, mem)) => duOp (I.REF_ (I.MEM (ty, mem)))
        | I.X86 (I.X86FDIVR_ST (st1, st2)) => duEmpty
        | I.X86 (I.X86FDIVRP st1) => duEmpty
        | I.X86 (I.X86FABS) => duEmpty
        | I.X86 (I.X86FCHS) => duEmpty
        | I.X86 (I.X86FFREE st) => duEmpty
        | I.X86 (I.X86FXCH st) => duEmpty
        | I.X86 (I.X86FUCOM st) => duEmpty
        | I.X86 (I.X86FUCOMP st) => duEmpty
        | I.X86 I.X86FUCOMPP => duEmpty
(*
        | I.X86 (I.X86FSTSW (dst, insn)) =>
          defuseInsn varSet duDst insn ++ duDst dst
*)
        | I.X86 (I.X86FSW_GT {clob}) => duEmpty
        | I.X86 (I.X86FSW_GE {clob}) => duEmpty
        | I.X86 (I.X86FSW_EQ {clob}) => duEmpty
        | I.X86 (I.X86FLDCW mem) => duOp (I.REF_ (I.MEM (I.Int16 I.U, mem)))
        | I.X86 (I.X86FNSTCW mem) => duDst (I.MEM (I.Int16 I.U, mem))
        | I.X86 I.X86FWAIT => duEmpty
        | I.X86 I.X86FNCLEX => duEmpty
      end

  fun defuseLast (func as {varSet, slotSet, duDst}) insn =
      let
        val defuseInsn = defuseInsn func
        val duOp = duOp duDst
        val duAddr = duAddr varSet
      in
        case insn of
          I.HANDLE (insn, _) => defuseInsn insn
        | I.CJUMP {test, cc, thenLabel, elseLabel} => defuseInsn test
        | I.CALL {callTo, returnTo, handler, defs, uses,
                  needStabilize, postFrameAdjust} =>
          {defs = varSet defs, uses = varSet uses} ++ duAddr callTo
        | I.JUMP {jumpTo, destinations} => duAddr jumpTo
        | I.UNWIND_JUMP {jumpTo, sp, fp, uses, handler} =>
          useSet (varSet uses) ++ duOp sp ++ duOp fp ++ duAddr jumpTo
        | I.TAILCALL_JUMP {preFrameSize, jumpTo, uses} =>
          useSet (varSet uses) ++ duAddr jumpTo
        | I.RETURN {preFrameSize, stubOptions, uses} =>
          useSet (varSet uses)
        | I.EXIT => duEmpty
      end

  fun defuseFirst varSet insn =
      case insn of
        I.BEGIN {label, align, loc} => duEmpty
      | I.CODEENTRY {label, symbol, scope, align, preFrameSize,
                     stubOptions, defs, loc} =>
        defSet (varSet defs)
      | I.HANDLERENTRY {label, align, defs, loc} => defSet (varSet defs)
      | I.ENTER => duEmpty

  fun clobsInsn insn =
      case insn of
        I.NOP => emptySet
      | I.STABILIZE => emptySet
      | I.REQUEST_SLOT slot => emptySet
      | I.REQUIRE_SLOT slot => emptySet
      | I.USE ops => emptySet
      | I.COMPUTE_FRAME {uses, clobs} => varSet clobs
      | I.MOVE (ty, dst, op1) => emptySet
      | I.MOVEADDR (ty, dst, addr) => emptySet
      | I.COPY {ty, dst:I.dst, src:I.operand, clobs} => varSet clobs
      | I.MLOAD {ty, dst:I.slot, srcAddr, size, defs, clobs} => varSet clobs
      | I.MSTORE {ty, dstAddr, src:I.slot, size, defs, clobs, global} =>
        varSet clobs
      | I.EXT8TO32 (_, dst, op1) => emptySet
      | I.EXT16TO32 (_, dst, op1) => emptySet
      | I.EXT32TO64 (_, dst, op1) => emptySet
      | I.DOWN32TO8 (_, dst, op1) => emptySet
      | I.DOWN32TO16 (_, dst, op1) => emptySet
      | I.ADD (ty, dst, op1, op2) => emptySet
      | I.SUB (ty, dst, op1, op2) => emptySet
      | I.MUL ((_,dst), (_,op1), (_,op2)) => emptySet
      | I.DIVMOD ({div=(_,ddiv), mod=(_,dmod)}, (_,op1), (_,op2)) => emptySet
      | I.AND (ty, dst, op1, op2) => emptySet
      | I.OR (ty, dst, op1, op2) => emptySet
      | I.XOR (ty, dst, op1, op2) => emptySet
      | I.LSHIFT (ty, dst, op1, op2) => emptySet
      | I.RSHIFT (ty, dst, op1, op2) => emptySet
      | I.ARSHIFT (ty, dst, op1, op2) => emptySet
      | I.TEST_SUB (_, op1, op2) => emptySet
      | I.TEST_AND (_, op1, op2) => emptySet
      | I.TEST_LABEL (_, op1, l) => emptySet
      | I.NOT (ty, dst, op1) => emptySet
      | I.NEG (ty, dst, op1) => emptySet
      | I.SET (cc1, ty, dst, {test}) => clobsInsn test
      | I.LOAD_FP dst => emptySet
      | I.LOAD_SP dst => emptySet
      | I.LOAD_PREV_FP dst => emptySet
      | I.LOAD_RETADDR dst => emptySet
      | I.LOADABSADDR {ty, dst, symbol, thunk} => emptySet
      | I.X86 (I.X86LEAINT (ty, dst, {base, shift, offset, disp})) => emptySet
      | I.X86 (I.X86FLD (ty, mem)) => emptySet
      | I.X86 (I.X86FLD_ST st) => emptySet
      | I.X86 (I.X86FST (ty, mem)) => emptySet
      | I.X86 (I.X86FSTP (ty, mem)) => emptySet
      | I.X86 (I.X86FSTP_ST st) => emptySet
      | I.X86 (I.X86FADD (ty, mem)) => emptySet
      | I.X86 (I.X86FADD_ST (st1, st2)) => emptySet
      | I.X86 (I.X86FADDP st1) => emptySet
      | I.X86 (I.X86FSUB (ty, mem)) => emptySet
      | I.X86 (I.X86FSUB_ST (st1, st2)) => emptySet
      | I.X86 (I.X86FSUBP st1) => emptySet
      | I.X86 (I.X86FSUBR (ty, mem)) => emptySet
      | I.X86 (I.X86FSUBR_ST (st1, st2)) => emptySet
      | I.X86 (I.X86FSUBRP st1) => emptySet
      | I.X86 (I.X86FMUL (ty, mem)) => emptySet
      | I.X86 (I.X86FMUL_ST (st1, st2)) => emptySet
      | I.X86 (I.X86FMULP st1) => emptySet
      | I.X86 (I.X86FDIV (ty, mem)) => emptySet
      | I.X86 (I.X86FDIV_ST (st1, st2)) => emptySet
      | I.X86 (I.X86FDIVP st1) => emptySet
      | I.X86 (I.X86FDIVR (ty, mem)) => emptySet
      | I.X86 (I.X86FDIVR_ST (st1, st2)) => emptySet
      | I.X86 (I.X86FDIVRP st1) => emptySet
      | I.X86 (I.X86FABS) => emptySet
      | I.X86 (I.X86FCHS) => emptySet
      | I.X86 (I.X86FFREE st) => emptySet
      | I.X86 (I.X86FXCH st) => emptySet
      | I.X86 (I.X86FUCOM st) => emptySet
      | I.X86 (I.X86FUCOMP st) => emptySet
      | I.X86 I.X86FUCOMPP => emptySet
      | I.X86 (I.X86FSW_GT {clob}) => varSet [clob]
      | I.X86 (I.X86FSW_GE {clob}) => varSet [clob]
      | I.X86 (I.X86FSW_EQ {clob}) => varSet [clob]
      | I.X86 (I.X86FLDCW mem) => emptySet
      | I.X86 (I.X86FNSTCW mem) => emptySet
      | I.X86 I.X86FWAIT => emptySet
      | I.X86 I.X86FNCLEX => emptySet

  fun clobsLast insn =
      case insn of
        I.HANDLE (insn, _) => clobsInsn insn
      | I.CJUMP {test, cc, thenLabel, elseLabel} => clobsInsn test
      | I.CALL {callTo, returnTo, handler, defs, uses,
                needStabilize, postFrameAdjust} => emptySet
      | I.JUMP {jumpTo, destinations} => emptySet
      | I.UNWIND_JUMP {jumpTo, sp, fp, uses, handler} => emptySet
      | I.TAILCALL_JUMP {preFrameSize, jumpTo, uses} => emptySet
      | I.RETURN {preFrameSize, stubOptions, uses} => emptySet
      | I.EXIT => emptySet

  fun clobsFirst insn =
      case insn of
        I.BEGIN {label, align, loc} => emptySet
      | I.CODEENTRY {label, symbol, scope, align, preFrameSize,
                     stubOptions, defs, loc} => emptySet
      | I.HANDLERENTRY {label, align, defs, loc} => emptySet
      | I.ENTER => emptySet

  structure Var =
  struct
    type set = I.var set
    type defuseSet = I.var defuseSet
    val format_set = format_set I.format_var
    val setUnion = setUnion : set * set -> set
    val setMinus = setMinus : set * set -> set
    val setIsSubset = setIsSubset : set * set -> bool
    val fold = LocalVarID.Map.foldl
    val filter = LocalVarID.Map.filter
    val inDomain = LocalVarID.Map.inDomain
    val find = LocalVarID.Map.find
    val isEmpty = LocalVarID.Map.isEmpty
    val emptySet = emptySet : set
    val singleton = fn x => singleton #id x : set
    val fromList = varSet
    fun slotSet (v:I.slot list) = emptySet
    val func = {varSet=varSet, slotSet=slotSet, duDst=duDstVar}
    val defuseFirst = fn x => defuseFirst varSet x
    val defuseInsn = fn x => defuseInsn func x
    val defuseLast = fn x => defuseLast func x
    fun defuse (RTLEdit.FIRST first) = defuseFirst first
      | defuse (RTLEdit.MIDDLE insn) = defuseInsn insn
      | defuse (RTLEdit.LAST last) = defuseLast last
    val clobsFirst = clobsFirst
    val clobsInsn = clobsInsn
    val clobsLast = clobsLast
    fun clobs (RTLEdit.FIRST first) = clobsFirst first
      | clobs (RTLEdit.MIDDLE insn) = clobsInsn insn
      | clobs (RTLEdit.LAST last) = clobsLast last
  end

  structure Slot =
  struct
    type set = I.slot set
    type defuseSet = I.slot defuseSet
    val format_set = format_set I.format_slot
    val setUnion = setUnion : set * set -> set
    val setMinus = setMinus : set * set -> set
    val setIsSubset = setIsSubset : set * set -> bool
    val fold = LocalVarID.Map.foldl
    val filter = LocalVarID.Map.filter
    val inDomain = LocalVarID.Map.inDomain
    val find = LocalVarID.Map.find
    val isEmpty = LocalVarID.Map.isEmpty
    val emptySet = emptySet : set
    val singleton = fn x => singleton #id x : set
    val fromList = slotSet
    fun varSet (v:I.var list) = emptySet
    val func = {varSet=varSet, slotSet=slotSet, duDst=duDstSlot}
    val defuseFirst = fn x => defuseFirst varSet x
    val defuseInsn = fn x => defuseInsn func x
    val defuseLast = fn x => defuseLast func x
    fun defuse (RTLEdit.FIRST first) = defuseFirst first
      | defuse (RTLEdit.MIDDLE insn) = defuseInsn insn
      | defuse (RTLEdit.LAST last) = defuseLast last
  end

  (********************************)


  fun labelPtrTy label =
      case label of
        I.LABEL _ => I.Code
      | I.SYMBOL (ptrTy,_,_) => ptrTy
      | I.CURRENT_POSITION => I.Code
      | I.LINK_ENTRY _ => I.Void
      | I.LINK_STUB _ => I.Code
      | I.ELF_GOT => I.Void
      | I.NULL ptrTy => ptrTy
      | I.LABELCAST (ptrTy, _) => ptrTy

  fun labelTy label =
      I.Ptr (labelPtrTy label)

  fun constTy const =
      case const of
        I.SYMOFFSET {base, label} => I.PtrDiff (labelPtrTy label)
      | I.INT64 _ => I.Int64 I.S
      | I.UINT64 _ => I.Int64 I.U
      | I.INT32 _ => I.Int32 I.S
      | I.UINT32 _ => I.Int32 I.U
      | I.INT16 _ => I.Int16 I.S
      | I.UINT16 _ => I.Int16 I.U
      | I.INT8 _ => I.Int8 I.S
      | I.UINT8 _ => I.Int8 I.U
      | I.REAL32 _ => I.Real32
      | I.REAL64 _ => I.Real64
      | I.REAL64HI _ => I.NoType
      | I.REAL64LO _ => I.NoType

  fun addrTy addr =
      case addr of
        I.ADDRCAST (ptrTy, _) => ptrTy
      | I.ABSADDR label => labelPtrTy label
      | I.DISP (_, addr) =>
        (
          case addrTy addr of
            I.Data => I.Void
          | I.Code => I.Code
          | I.Void => I.Void
        )
      | I.BASE {id, ty=I.Ptr ptrTy} => ptrTy
      | I.BASE {id, ty=I.Atom} => I.Void
      | I.BASE _ => raise Control.Bug "addrTy: BASE"
      | ABSINDEX {base, index, scale} =>
        (
          case labelPtrTy base of
            I.Data => I.Void
          | I.Code => I.Code
          | I.Void => I.Void
        )
      | BASEINDEX {base={id,ty=I.Ptr ptrTy}, index, scale} =>
        (
          case ptrTy of
            I.Data => I.Void
          | I.Code => I.Code
          | I.Void => I.Void
        )
      | BASEINDEX {base={id,ty=I.Atom}, index, scale} => I.Void
      | BASEINDEX {base, index, scale} => raise Control.Bug "addrTy: BASEINDEX"
      | POSTFRAME {offset, size} => I.Void
      | PREFRAME {offset, size} => I.Void
      | WORKFRAME _ => I.Void
      | FRAMEINFO _ => I.Void

  fun dstTy dst =
      case dst of
        I.REG {id, ty} => ty
      | I.MEM (ty, _) => ty
      | I.COUPLE (ty, _) => ty

  fun operandTy operand =
      case operand of
        I.CONST c => constTy c
      | I.REF (I.N, dst) => dstTy dst
      | I.REF (I.CAST ty, _) => ty

  (********************************)

  fun handlerLabels I.NO_HANDLER = nil
    | handlerLabels (I.HANDLER {handlers, ...}) = handlers

  fun successors last =
      case last of
        I.HANDLE (_, {nextLabel, handler}) =>
        nextLabel :: handlerLabels handler
      | I.CJUMP {test, cc, thenLabel, elseLabel} => [thenLabel, elseLabel]
      | I.CALL {callTo, returnTo, handler, defs, uses, needStabilize,
                postFrameAdjust} =>
        returnTo :: handlerLabels handler
      | I.JUMP {jumpTo, destinations} => destinations
      | I.UNWIND_JUMP {jumpTo, fp, sp, uses, handler} => handlerLabels handler
      | I.TAILCALL_JUMP {preFrameSize, jumpTo, uses} => nil
      | I.RETURN {preFrameSize, stubOptions, uses} => nil
      | I.EXIT => nil

(*
  fun edges graph =
      let
        fun add updateFn (key, map) =
            I.LabelMap.insert
              (map, key, updateFn (case I.LabelMap.find (map, key) of
                                     NONE => {succs=nil, preds=nil}
                                   | SOME x => x))

        fun addEdges (edgeMap, from, succs) =
            foldl (add (fn {succs,preds} => {succs=succs,preds=from::preds}))
                  (add (fn {succs=l,preds} => {succs=l@succs,preds=preds})
                       (from, edgeMap))
                  succs
      in
        I.LabelMap.foldli
          (fn (label, (_,_,last):I.block, {edges, exits}) =>
              case successors last of
                nil => {edges = edges, exits = label::exits}
              | succs => {edges = addEdges (edges, label, succs),
                          exits = exits})
          {edges = I.LabelMap.empty, exits = nil}
          graph
      end
*)

  fun format_labelList labels =
      SMLFormat.BasicFormatters.format_list
        (I.format_label, SMLFormat.BasicFormatters.format_string ",")
        labels

  fun format_edges {succs, preds} =
      SMLFormat.BasicFormatters.format_string "succs: " @
      format_labelList succs @
      [SMLFormat.FormatExpression.Newline] @
      SMLFormat.BasicFormatters.format_string "preds: " @
      format_labelList preds

  fun edges graph =
      I.LabelMap.foldli
        (fn (label, (_, _, last), graph) =>
            case successors last of
              nil => graph
            | succs =>
              let
                val focus = RTLEdit.focusBlock (graph, label)
                val {preds, ...} = RTLEdit.annotation focus
                val ann = {succs = succs, preds = preds}
                val focus = RTLEdit.setAnnotation (focus, ann)
                val graph = RTLEdit.unfocusBlock focus
              in
                foldl (fn (to, graph) =>
                          let
                            val focus = RTLEdit.focusBlock (graph, to)
                            val {preds, succs} = RTLEdit.annotation focus
                            val ann = {succs = succs, preds = label::preds}
                            val focus = RTLEdit.setAnnotation (focus, ann)
                          in
                            RTLEdit.unfocusBlock focus
                          end)
                      graph
                      succs
              end)
        (RTLEdit.annotate (graph, {succs=nil, preds=nil}))
        graph

  local
    fun entries (graph:I.graph) =
        I.LabelMap.foldri
          (fn (l, (I.CODEENTRY _, _, _), z) => l::z
            | (l, (I.ENTER, _, _), z) => l::z
            | (l, (I.HANDLERENTRY _, _, _), z) => z
            | (l, (I.BEGIN _, _, _), z) => z)
          nil
          graph

    fun succ (graph:I.graph, label) =
        case I.LabelMap.find (graph, label) of
          SOME (_,_,l) => successors l
        | NONE => raise Control.Bug ("preorder: "
                                     ^ Control.prettyPrint (I.format_label label))
  in

  fun postorder graph =
      let
        fun visit (visited, nil, l) = l
          | visit (visited, h::t, l) =
            if I.LabelSet.member (visited, h)
            then visit (visited, t, l)
            else visit (I.LabelSet.add (visited, h), succ (graph, h) @ t, h::l)
      in
        visit (I.LabelSet.empty, entries graph, nil)
      end

  fun preorder graph =
      rev (postorder graph)

  end (* local *)

  (********************************)

  type 'a analysis =
      {
        init: 'a,
        join: 'a * 'a -> 'a,
        pass: RTLEdit.node * 'a -> 'a,
        filterIn: RTL.label * 'a -> 'a,
        filterOut: RTL.label * 'a -> 'a,
        changed: {old:'a, new:'a} -> bool
      }

  type 'a answer =
      {
        succs: RTL.label list,
        preds: RTL.label list,
        answerIn: 'a,
        answerOut: 'a
      }

  local
    open SMLFormat.BasicFormatters
    open SMLFormat.FormatExpression
    fun format_labelList labels =
        format_list (I.format_label, format_string ",") labels
  in
  fun format_answer fmt {succs, preds, answerIn, answerOut} =
      format_string "succs: " @ format_labelList succs @ [Newline] @
      format_string "preds: " @ format_labelList preds @ [Newline] @
      format_string "answerIn: " @ [Guard (NONE, fmt answerIn)] @ [Newline] @
      format_string "answerOut: " @ [Guard (NONE, fmt answerOut)]
  end

  fun answerInOf (graph:'a answer RTLEdit.annotatedGraph, label) =
      #answerIn (RTLEdit.annotation (RTLEdit.focusBlock (graph, label)))
  fun answerOutOf (graph:'a answer RTLEdit.annotatedGraph, label) =
      #answerOut (RTLEdit.annotation (RTLEdit.focusBlock (graph, label)))

  local
    type set = I.label list * I.LabelSet.set

    fun initSet l = (l, I.LabelSet.fromList l) : set
    fun enqueue (q, l2) =
        foldl (fn (l,(l1,set)) =>
                  if I.LabelSet.member (set, l) then (l1,set)
                  else (l::l1, I.LabelSet.add (set, l)))
              q
              l2
    fun dequeue ((h::t, set):set) =
        SOME (h, (t, I.LabelSet.delete (set, h)):set)
      | dequeue (nil, set) =
            case I.LabelSet.listItems set of
              nil => NONE
            | h::t => SOME (h, (t, I.LabelSet.delete (set, h)):set)
(*
    type set = I.label list
    fun initSet l = l
    fun enqueue (l1,l2) = l1 @ l2
    fun dequeue (h::t) = SOME (h, t) | dequeue nil = NONE
*)
  in

  fun analyzeFlowBackward ({init, join, pass, filterIn, filterOut,
                            changed}:'a analysis)
                          graph =
      let
        val workSet = initSet (postorder graph)
        val graph = edges graph
        val graph = RTLEdit.map (fn {succs, preds} =>
                                    {succs = succs,
                                     preds = preds,
                                     answerIn = init,
                                     answerOut = init})
                                graph
(*
        val count = ref 0
*)

        fun loop (workSet, graph) =
            case dequeue workSet of
              NONE => graph
            | SOME (label, workSet) =>
              let
(*
val _ = count := !count + 1
*)
              val focus = RTLEdit.focusBlock (graph, label)
              val {preds, succs, answerIn, answerOut} = RTLEdit.annotation focus
              val newOut =
                  foldl (fn (l, out) => join (out, answerInOf (graph, l)))
                        answerOut succs
              val newOut = filterOut (label, newOut)
              val newIn = RTLEdit.foldBackward pass newOut focus
              val newIn = filterIn (label, newIn)
              val workSet =
                  if changed {old=answerIn, new=newIn}
                  then enqueue (workSet, preds)
                  else workSet
              val focus = RTLEdit.setAnnotation (focus, {preds = preds,
                                                         succs = succs,
                                                         answerIn = newIn,
                                                         answerOut = newOut})
            in
              loop (workSet, RTLEdit.unfocusBlock focus)
            end
      in
        loop (workSet, graph)
(*
        before (let open FormatByHand in put (%`"analyzeFlowBackward: "%pi"/"%pi""` (!count) (I.LabelMap.numItems (RTLEdit.graph graph)));() end)
*)
      end
        
  fun analyzeFlowForward ({init, join, pass, filterIn, filterOut,
                           changed}:'a analysis)
                         graph =
      let
        val workSet = initSet (preorder graph)
        val graph = edges graph
        val graph = RTLEdit.map (fn {succs, preds} =>
                                    {succs = succs,
                                     preds = preds,
                                     answerIn = init,
                                     answerOut = init})
                                graph
(*
        val count = ref 0
*)

        fun loop (workSet, graph) =
            case dequeue workSet of
              NONE => graph
            | SOME (label, workSet) =>
              let
(*
val _ = count := !count + 1
*)
              val focus = RTLEdit.focusBlock (graph, label)
              val {preds, succs, answerIn, answerOut} = RTLEdit.annotation focus
              val newIn =
                  foldl (fn (l, ansIn) => join (ansIn, answerOutOf (graph, l)))
                        answerIn preds
              val newIn = filterIn (label, newIn)
              val newOut = RTLEdit.foldForward pass newIn focus
              val newOut = filterOut (label, newOut)

              val workSet =
                  if changed {old=answerOut, new=newOut}
                  then enqueue (workSet, succs)
                  else workSet
              val focus = RTLEdit.setAnnotation (focus, {preds = preds,
                                                         succs = succs,
                                                         answerIn = newIn,
                                                         answerOut = newOut})
            in
              loop (workSet, RTLEdit.unfocusBlock focus)
            end
      in
        loop (workSet, graph)
(*
        before (let open FormatByHand in put (%`"analyzeFlowForward: "%pi"/"%pi""` (!count) (I.LabelMap.numItems (RTLEdit.graph graph)));() end)
*)
      end

  end (* local *)

(*
  fun analyzeFlowBackward ({init, join, pass, changed}:'a analysis) graph =
      let
        val {edges, exits} = edges graph

val _ = puts "== edges"
val _ = I.LabelMap.appi
        (fn (id, {succs, preds}) =>
            puts (LocalVarID.toString id ^ ": succs=" ^
                  foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" succs ^ " preds=" ^
                  foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" preds))
        edges
val _ = puts "--"
val _ = puts (foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" exits)
val _ = puts "=="

        val answer = I.LabelMap.empty

        fun loop (nil, answer) = answer
          | loop (label::workSet, answer) =
            let
val _ = puts ("workset: " ^
              foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" (label::workSet))

              val {preds, succs} = I.LabelMap.lookup (edges, label)
              val {answerIn, answerOut} = answerOf (answer, label, init)
              val newOut =
                  foldl (fn (l, out) =>
                            join (out, answerInOf (answer, l, init)))
                        answerOut succs
              val block = I.LabelMap.lookup (graph, label)
              val newIn = RTLEdit.foldBlockBackward pass newOut block
val _ = puts ("changed: " ^ (if changed {old=answerIn, new=newIn} then "true" else "false"))
              val workSet =
                  if changed {old=answerIn, new=newIn}
                  then preds @ workSet
                  else workSet
              val answer = I.LabelMap.insert (answer, label,
                                              {answerIn = newIn,
                                               answerOut = newOut})
            in
              loop (workSet, answer)
            end
      in
        loop (exits, I.LabelMap.empty)
      end

  type 'a answer =
      {answerIn: 'a, answerOut: 'a} RTL.LabelMap.map

  type 'a analysis =
      {
        init: 'a,
        join: 'a * 'a -> 'a,
        pass: RTLEdit.node * 'a -> 'a,
        changed: {old:'a, new:'a} -> bool
      }

  local
    fun answerOf (answer, label, init) =
        case I.LabelMap.find (answer, label) of
          NONE => {answerIn = init, answerOut = init}
        | SOME x => x
    fun answerInOf x = #answerIn (answerOf x)
    fun answerOutOf x = #answerOut (answerOf x)
  in

  fun analyzeFlowBackward ({init, join, pass, changed}:'a analysis) graph =
      let
        val {edges, exits} = edges graph

val _ = puts "== edges"
val _ = I.LabelMap.appi
        (fn (id, {succs, preds}) =>
            puts (LocalVarID.toString id ^ ": succs=" ^
                  foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" succs ^ " preds=" ^
                  foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" preds))
        edges
val _ = puts "--"
val _ = puts (foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" exits)
val _ = puts "=="

        val answer = I.LabelMap.empty

        fun loop (nil, answer) = answer
          | loop (label::workSet, answer) =
            let
val _ = puts ("workset: " ^
              foldl (fn (x,z) => z ^","^ Control.prettyPrint (I.format_label x)) "" (label::workSet))

              val {preds, succs} = I.LabelMap.lookup (edges, label)
              val {answerIn, answerOut} = answerOf (answer, label, init)
              val newOut =
                  foldl (fn (l, out) =>
                            join (out, answerInOf (answer, l, init)))
                        answerOut succs
              val block = I.LabelMap.lookup (graph, label)
              val newIn = RTLEdit.foldBlockBackward pass newOut block
val _ = puts ("changed: " ^ (if changed {old=answerIn, new=newIn} then "true" else "false"))
              val workSet =
                  if changed {old=answerIn, new=newIn}
                  then preds @ workSet
                  else workSet
              val answer = I.LabelMap.insert (answer, label,
                                              {answerIn = newIn,
                                               answerOut = newOut})
            in
              loop (workSet, answer)
            end
      in
        loop (exits, I.LabelMap.empty)
      end

  fun analyzeFlowForward ({init, join, pass, changed}:'a analysis) graph =
      let
        val {edges, exits} = edges graph
        val answer = I.LabelMap.empty

        fun loop (nil, answer) = answer
          | loop (label::workSet, answer) =
            let
              val {preds, succs} = I.LabelMap.lookup (edges, label)
              val {answerIn, answerOut} = answerOf (answer, label, init)
              val newIn =
                  foldl (fn (l, newIn) =>
                            join (newIn, answerOutOf (answer, l, init)))
                        answerIn preds
              val block = I.LabelMap.lookup (graph, label)
              val newOut = RTLEdit.foldBlockForward pass newIn block
              val workSet =
                  if changed {old=answerOut, new=newOut}
                  then preds @ workSet
                  else workSet
              val answer = I.LabelMap.insert (answer, label,
                                              {answerIn = newIn,
                                               answerOut = newOut})
            in
              loop (workSet, answer)
            end
      in
        loop (exits, I.LabelMap.empty)
      end

  end (* local *)
*)

end
