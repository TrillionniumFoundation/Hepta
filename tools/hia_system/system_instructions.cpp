// SPDX-License-Identifier: MIT
// Executable instruction codec for HIA's explicit unsafe systems dialect.
// Every instruction is reconstructed from typed HIA operands and properties.
// There is deliberately no LLVM-assembly body, clone, or native-object fallback.
#include "system_wire.h"

#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Support/Casting.h"

static_assert(LLVM_VERSION_MAJOR == 20 && LLVM_VERSION_MINOR == 1 &&
                  LLVM_VERSION_PATCH == 8,
              "The HIA systems instruction schema is pinned to LLVM 20.1.8");

namespace hia {
namespace {
using namespace llvm;

// Required fields and a closed attribute set make unsupported refinements fail
// closed. The enclosing module codec owns id, name, and metadata.
class Fields {
  const O &Object;
  std::set<std::string> Read;
public:
  explicit Fields(const O &Object) : Object(Object) {}
  const J &get(StringRef Key) {
    Read.insert(Key.str());
    const J *V = Object.get(Key);
    if (!V)
      fail(Twine("missing instruction field: ") + Key);
    return *V;
  }
  StringRef str(StringRef Key) {
    auto S = get(Key).getAsString();
    if (!S)
      fail(Twine("expected instruction string: ") + Key);
    return *S;
  }
  bool boolean(StringRef Key) {
    auto B = get(Key).getAsBoolean();
    if (!B)
      fail(Twine("expected instruction boolean: ") + Key);
    return *B;
  }
  uint64_t integer(StringRef Key, uint64_t Max = UINT64_MAX) {
    auto I = get(Key).getAsInteger();
    if (!I || *I < 0 || uint64_t(*I) > Max)
      fail(Twine("invalid instruction integer: ") + Key);
    return uint64_t(*I);
  }
  unsigned count(StringRef Key) {
    return unsigned(integer(Key, std::numeric_limits<unsigned>::max()));
  }
  const A &array(StringRef Key) {
    const A *V = get(Key).getAsArray();
    if (!V)
      fail(Twine("expected instruction array: ") + Key);
    return *V;
  }
  const O &object(StringRef Key) {
    const O *V = get(Key).getAsObject();
    if (!V)
      fail(Twine("expected instruction object: ") + Key);
    return *V;
  }
  void finish(bool IsInstruction = false) const {
    for (const auto &KV : Object) {
      StringRef Key = KV.first;
      if (Read.count(Key.str()))
        continue;
      if (IsInstruction &&
          (Key == "id" || Key == "name" || Key == "metadata"))
        continue;
      fail(Twine("unconsumed instruction field: ") + Key);
    }
  }
};

unsigned opcode(StringRef Name) {
  // Instruction.def supplies a closed list; LLVM's reserved UserOp slots do not
  // represent executable source instructions.
#define HANDLE_INST(N, OP, CLASS) \
  if (Name == Instruction::getOpcodeName(N)) { \
    if (N == Instruction::UserOp1 || N == Instruction::UserOp2) \
      fail("reserved instruction opcode"); \
    return N; \
  }
#include "llvm/IR/Instruction.def"
  fail(Twine("unsupported HIA systems opcode: ") + Name);
}

bool overflowFlags(unsigned Op) {
  return Op == Instruction::Add || Op == Instruction::Sub ||
         Op == Instruction::Mul || Op == Instruction::Shl ||
         Op == Instruction::Trunc;
}
bool exactFlag(unsigned Op) {
  return Op == Instruction::UDiv || Op == Instruction::SDiv ||
         Op == Instruction::LShr || Op == Instruction::AShr;
}

std::string syncScope(const Instruction &I, SyncScope::ID ID) {
  auto Name = I.getContext().getSyncScopeName(ID);
  if (!Name)
    fail("unknown LLVM synchronization scope ID");
  return Name->str();
}
SyncScope::ID syncScope(Fields &F, Decoder &D) {
  return D.context().getOrInsertSyncScopeID(F.str("sync_scope"));
}
AtomicOrdering ordering(Fields &F, StringRef Key) {
  StringRef Name = F.str(Key);
  for (unsigned N : {0U, 1U, 2U, 4U, 5U, 6U, 7U}) {
    auto Order = static_cast<AtomicOrdering>(N);
    if (Name == toIRString(Order))
      return Order;
  }
  fail(Twine("invalid atomic ordering: ") + Name);
}
Align alignment(Fields &F) {
  uint64_t N = F.integer("align", uint64_t(1) << 32);
  if (!N || (N & (N - 1)))
    fail("instruction alignment must be a nonzero power of two");
  return Align(N);
}
BasicBlock *asBlock(Value *V) {
  auto *B = dyn_cast<BasicBlock>(V);
  if (!B)
    fail("instruction destination is not a basic block");
  return B;
}
void requirePointer(Value *V) {
  if (!V->getType()->isPointerTy())
    fail("memory instruction requires a scalar pointer");
}
void sameType(Value *L, Value *R) {
  if (L->getType() != R->getType())
    fail("instruction operand types disagree");
}
std::vector<unsigned> indices(Fields &F) {
  std::vector<unsigned> Out;
  for (const J &V : F.array("indices")) {
    auto I = V.getAsInteger();
    if (!I || *I < 0 || uint64_t(*I) > UINT32_MAX)
      fail("invalid aggregate index");
    Out.push_back(unsigned(*I));
  }
  if (Out.empty())
    fail("aggregate instruction requires an index");
  return Out;
}
CmpInst::Predicate predicate(Fields &F, bool IsInteger) {
  StringRef Name = F.str("predicate");
  unsigned First = IsInteger ? CmpInst::FIRST_ICMP_PREDICATE
                             : CmpInst::FIRST_FCMP_PREDICATE;
  unsigned Last = IsInteger ? CmpInst::LAST_ICMP_PREDICATE
                            : CmpInst::LAST_FCMP_PREDICATE;
  for (unsigned N = First; N <= Last; ++N) {
    auto P = static_cast<CmpInst::Predicate>(N);
    if (Name == CmpInst::getPredicateName(P))
      return P;
  }
  fail(Twine("invalid comparison predicate: ") + Name);
}

void encodeFlags(O &Out, const Instruction &I) {
  unsigned Op = I.getOpcode();
  if (overflowFlags(Op)) {
    Out["nuw"] = I.hasNoUnsignedWrap();
    Out["nsw"] = I.hasNoSignedWrap();
  }
  if (exactFlag(Op))
    Out["exact"] = I.isExact();
  if (isa<PossiblyNonNegInst>(I))
    Out["nneg"] = I.hasNonNeg();
  if (auto *P = dyn_cast<PossiblyDisjointInst>(&I))
    Out["disjoint"] = P->isDisjoint();
  if (auto *C = dyn_cast<ICmpInst>(&I))
    Out["samesign"] = C->hasSameSign();
  if (isa<FPMathOperator>(I)) {
    Out["fast_math"] = O{
      {"reassoc", I.hasAllowReassoc()}, {"nnan", I.hasNoNaNs()},
      {"ninf", I.hasNoInfs()}, {"nsz", I.hasNoSignedZeros()},
      {"arcp", I.hasAllowReciprocal()}, {"contract", I.hasAllowContract()},
      {"afn", I.hasApproxFunc()}};
  }
}
void decodeFlags(Fields &F, Instruction &I) {
  unsigned Op = I.getOpcode();
  if (overflowFlags(Op)) {
    I.setHasNoUnsignedWrap(F.boolean("nuw"));
    I.setHasNoSignedWrap(F.boolean("nsw"));
  }
  if (exactFlag(Op))
    I.setIsExact(F.boolean("exact"));
  if (isa<PossiblyNonNegInst>(I))
    I.setNonNeg(F.boolean("nneg"));
  if (auto *P = dyn_cast<PossiblyDisjointInst>(&I))
    P->setIsDisjoint(F.boolean("disjoint"));
  if (auto *C = dyn_cast<ICmpInst>(&I))
    C->setSameSign(F.boolean("samesign"));
  if (isa<FPMathOperator>(I)) {
    Fields M(F.object("fast_math"));
    I.setHasAllowReassoc(M.boolean("reassoc"));
    I.setHasNoNaNs(M.boolean("nnan"));
    I.setHasNoInfs(M.boolean("ninf"));
    I.setHasNoSignedZeros(M.boolean("nsz"));
    I.setHasAllowReciprocal(M.boolean("arcp"));
    I.setHasAllowContract(M.boolean("contract"));
    I.setHasApproxFunc(M.boolean("afn"));
    M.finish();
  }
}

void encodeCall(O &Out, const CallBase &Call, Encoder &E) {
  Out["function_type"] = E.type(Call.getFunctionType());
  Out["argument_count"] = int64_t(Call.arg_size());
  Out["calling_convention"] = int64_t(Call.getCallingConv());
  Out["attributes"] = E.attributes(Call.getAttributes());
  A Bundles;
  for (unsigned I = 0; I < Call.getNumOperandBundles(); ++I) {
    OperandBundleUse Bundle = Call.getOperandBundleAt(I);
    Bundles.push_back(O{{"tag", Bundle.getTagName()},
                        {"size", int64_t(Bundle.Inputs.size())}});
  }
  Out["bundles"] = std::move(Bundles);
  if (auto *C = dyn_cast<CallInst>(&Call)) {
    const char *Kind = nullptr;
    switch (C->getTailCallKind()) {
    case CallInst::TCK_None: Kind = "none"; break;
    case CallInst::TCK_Tail: Kind = "tail"; break;
    case CallInst::TCK_MustTail: Kind = "musttail"; break;
    case CallInst::TCK_NoTail: Kind = "notail"; break;
    }
    if (!Kind)
      fail("unsupported tail-call kind");
    Out["tail_kind"] = Kind;
  }
  if (auto *C = dyn_cast<CallBrInst>(&Call))
    Out["indirect_count"] = int64_t(C->getNumIndirectDests());
}

Instruction *decodeCall(unsigned Op, Fields &F, Decoder &D,
                        ArrayRef<Value *> Values, BasicBlock *Block) {
  auto *FT = dyn_cast<FunctionType>(D.type(F.get("function_type")));
  if (!FT)
    fail("call function_type is not a function type");
  unsigned Count = F.count("argument_count");
  if (Count > Values.size() || Count < FT->getNumParams() ||
      (!FT->isVarArg() && Count != FT->getNumParams()))
    fail("call argument count disagrees with function type");
  ArrayRef<Value *> Args = Values.take_front(Count);
  for (unsigned N = 0; N < FT->getNumParams(); ++N)
    if (Args[N]->getType() != FT->getParamType(N))
      fail("call argument type disagrees with function type");

  std::vector<OperandBundleDef> Bundles;
  size_t Position = Count;
  for (const J &V : F.array("bundles")) {
    const O *Obj = V.getAsObject();
    if (!Obj)
      fail("call operand bundle is not an object");
    Fields BF(*Obj);
    std::string Tag = BF.str("tag").str();
    unsigned Size = BF.count("size");
    BF.finish();
    if (Size > Values.size() - Position)
      fail("call bundle exceeds operand array");
    Bundles.emplace_back(std::move(Tag), Values.slice(Position, Size));
    Position += Size;
  }
  unsigned IndirectCount =
      Op == Instruction::CallBr ? F.count("indirect_count") : 0;
  uint64_t Trailing = Op == Instruction::Call ? 1 :
                      Op == Instruction::Invoke ? 3 :
                      uint64_t(IndirectCount) + 2;
  if (Values.size() - Position != Trailing)
    fail("call operand layout disagrees with bundle or successor counts");
  Value *Callee = Values.back();
  requirePointer(Callee);
  CallBase *Call = nullptr;
  if (Op == Instruction::Call) {
    auto *C = CallInst::Create(FT, Callee, Args, Bundles, "", Block);
    StringRef Tail = F.str("tail_kind");
    if (Tail == "none") C->setTailCallKind(CallInst::TCK_None);
    else if (Tail == "tail") C->setTailCallKind(CallInst::TCK_Tail);
    else if (Tail == "musttail") C->setTailCallKind(CallInst::TCK_MustTail);
    else if (Tail == "notail") C->setTailCallKind(CallInst::TCK_NoTail);
    else fail(Twine("unknown call tail kind: ") + Tail);
    Call = C;
  } else if (Op == Instruction::Invoke) {
    Call = InvokeInst::Create(FT, Callee, asBlock(Values[Position]),
                              asBlock(Values[Position + 1]), Args, Bundles,
                              "", Block);
  } else {
    std::vector<BasicBlock *> Destinations;
    for (unsigned N = 0; N < IndirectCount; ++N)
      Destinations.push_back(asBlock(Values[Position + 1 + N]));
    Call = CallBrInst::Create(FT, Callee, asBlock(Values[Position]),
                              Destinations, Args, Bundles, "", Block);
  }
  Call->setCallingConv(unsigned(F.integer("calling_convention",
                                         CallingConv::MaxID)));
  Call->setAttributes(D.attributes(F.get("attributes")));
  return Call;
}
} // namespace

O encodeInstruction(const llvm::Instruction &I, Encoder &E) {
  using namespace llvm;
  // This also rejects reserved/unrecognized opcode slots.
  opcode(I.getOpcodeName());
  O Out{{"op", I.getOpcodeName()}, {"result_type", E.type(I.getType())}};
  A Operands;
  for (const Use &U : I.operands())
    Operands.push_back(E.value(U.get()));
  Out["operands"] = std::move(Operands);
  encodeFlags(Out, I);

  if (auto *C = dyn_cast<CallBase>(&I))
    encodeCall(Out, *C, E);
  switch (I.getOpcode()) {
  case Instruction::Alloca: {
    const auto &X = cast<AllocaInst>(I);
    Out["allocated_type"] = E.type(X.getAllocatedType());
    Out["address_space"] = int64_t(X.getAddressSpace());
    Out["align"] = int64_t(X.getAlign().value());
    Out["inalloca"] = X.isUsedWithInAlloca();
    Out["swifterror"] = X.isSwiftError();
    break;
  }
  case Instruction::Load: {
    const auto &X = cast<LoadInst>(I);
    Out["align"] = int64_t(X.getAlign().value());
    Out["volatile"] = X.isVolatile();
    Out["ordering"] = toIRString(X.getOrdering());
    Out["sync_scope"] = syncScope(I, X.getSyncScopeID());
    break;
  }
  case Instruction::Store: {
    const auto &X = cast<StoreInst>(I);
    Out["align"] = int64_t(X.getAlign().value());
    Out["volatile"] = X.isVolatile();
    Out["ordering"] = toIRString(X.getOrdering());
    Out["sync_scope"] = syncScope(I, X.getSyncScopeID());
    break;
  }
  case Instruction::Fence: {
    const auto &X = cast<FenceInst>(I);
    Out["ordering"] = toIRString(X.getOrdering());
    Out["sync_scope"] = syncScope(I, X.getSyncScopeID());
    break;
  }
  case Instruction::AtomicCmpXchg: {
    const auto &X = cast<AtomicCmpXchgInst>(I);
    Out["align"] = int64_t(X.getAlign().value());
    Out["volatile"] = X.isVolatile();
    Out["weak"] = X.isWeak();
    Out["success_ordering"] = toIRString(X.getSuccessOrdering());
    Out["failure_ordering"] = toIRString(X.getFailureOrdering());
    Out["sync_scope"] = syncScope(I, X.getSyncScopeID());
    break;
  }
  case Instruction::AtomicRMW: {
    const auto &X = cast<AtomicRMWInst>(I);
    Out["operation"] = AtomicRMWInst::getOperationName(X.getOperation());
    Out["align"] = int64_t(X.getAlign().value());
    Out["volatile"] = X.isVolatile();
    Out["ordering"] = toIRString(X.getOrdering());
    Out["sync_scope"] = syncScope(I, X.getSyncScopeID());
    break;
  }
  case Instruction::GetElementPtr: {
    const auto &X = cast<GetElementPtrInst>(I);
    Out["source_element_type"] = E.type(X.getSourceElementType());
    Out["inbounds"] = X.isInBounds();
    Out["nusw"] = X.hasNoUnsignedSignedWrap();
    Out["nuw"] = X.hasNoUnsignedWrap();
    break;
  }
  case Instruction::ICmp:
  case Instruction::FCmp:
    Out["predicate"] = CmpInst::getPredicateName(cast<CmpInst>(I).getPredicate());
    break;
  case Instruction::PHI: {
    const auto &X = cast<PHINode>(I);
    A Blocks;
    for (unsigned N = 0; N < X.getNumIncomingValues(); ++N)
      Blocks.push_back(E.value(X.getIncomingBlock(N)));
    Out["incoming_blocks"] = std::move(Blocks);
    break;
  }
  case Instruction::ShuffleVector: {
    A Mask;
    for (int N : cast<ShuffleVectorInst>(I).getShuffleMask())
      Mask.push_back(int64_t(N));
    Out["mask"] = std::move(Mask);
    break;
  }
  case Instruction::ExtractValue: {
    A Indices;
    for (unsigned N : cast<ExtractValueInst>(I).getIndices())
      Indices.push_back(int64_t(N));
    Out["indices"] = std::move(Indices);
    break;
  }
  case Instruction::InsertValue: {
    A Indices;
    for (unsigned N : cast<InsertValueInst>(I).getIndices())
      Indices.push_back(int64_t(N));
    Out["indices"] = std::move(Indices);
    break;
  }
  case Instruction::LandingPad:
    Out["cleanup"] = cast<LandingPadInst>(I).isCleanup();
    break;
  case Instruction::CatchSwitch:
    Out["has_unwind"] = cast<CatchSwitchInst>(I).hasUnwindDest();
    break;
  default:
    break; // All remaining opcode semantics are solely operands and flags.
  }
  return Out;
}

llvm::Instruction *decodeInstruction(const O &Object, Decoder &D,
                                     llvm::BasicBlock *Block) {
  using namespace llvm;
  if (!Block)
    fail("instruction has no containing basic block");
  Fields F(Object);
  unsigned Op = opcode(F.str("op"));
  Type *ResultType = D.type(F.get("result_type"));
  std::vector<Value *> Storage;
  for (const J &V : F.array("operands"))
    Storage.push_back(D.value(V));
  ArrayRef<Value *> V(Storage);
  auto Arity = [&](size_t N) {
    if (V.size() != N)
      fail(Twine("operand count mismatch for ") + Instruction::getOpcodeName(Op));
  };
  Instruction *I = nullptr;

  if (Instruction::isBinaryOp(Op)) {
    Arity(2);
    sameType(V[0], V[1]);
    bool FP = Op == Instruction::FAdd || Op == Instruction::FSub ||
              Op == Instruction::FMul || Op == Instruction::FDiv ||
              Op == Instruction::FRem;
    if (FP ? !V[0]->getType()->isFPOrFPVectorTy()
           : !V[0]->getType()->isIntOrIntVectorTy())
      fail("binary instruction operand class is invalid");
    I = BinaryOperator::Create(static_cast<Instruction::BinaryOps>(Op),
                                V[0], V[1], "", Block);
  } else if (Instruction::isCast(Op)) {
    Arity(1);
    auto CastOp = static_cast<Instruction::CastOps>(Op);
    if (!CastInst::castIsValid(CastOp, V[0], ResultType))
      fail("invalid cast operand/result types");
    I = CastInst::Create(CastOp, V[0], ResultType, "", Block);
  } else {
    switch (Op) {
    case Instruction::FNeg:
      Arity(1);
      if (!V[0]->getType()->isFPOrFPVectorTy())
        fail("fneg requires floating point operands");
      I = UnaryOperator::Create(Instruction::FNeg, V[0], "", Block);
      break;
    case Instruction::Ret:
      if (V.size() > 1) fail("return has too many operands");
      I = ReturnInst::Create(D.context(), V.empty() ? nullptr : V[0], Block);
      break;
    case Instruction::Br:
      if (V.size() == 1)
        I = BranchInst::Create(asBlock(V[0]), Block);
      else {
        Arity(3);
        if (!V[0]->getType()->isIntegerTy(1))
          fail("branch condition is not i1");
        // LLVM stores [condition, false destination, true destination].
        I = BranchInst::Create(asBlock(V[2]), asBlock(V[1]), V[0], Block);
      }
      break;
    case Instruction::Switch: {
      if (V.size() < 2 || (V.size() % 2) != 0 ||
          !V[0]->getType()->isIntegerTy())
        fail("invalid switch operand layout");
      auto *S = SwitchInst::Create(V[0], asBlock(V[1]),
                                   unsigned((V.size() - 2) / 2), Block);
      for (size_t N = 2; N < V.size(); N += 2) {
        auto *C = dyn_cast<ConstantInt>(V[N]);
        if (!C || C->getType() != V[0]->getType())
          fail("invalid switch case constant");
        S->addCase(C, asBlock(V[N + 1]));
      }
      I = S;
      break;
    }
    case Instruction::IndirectBr: {
      if (V.empty()) fail("indirectbr has no address");
      requirePointer(V[0]);
      auto *B = IndirectBrInst::Create(V[0], unsigned(V.size() - 1), Block);
      for (size_t N = 1; N < V.size(); ++N)
        B->addDestination(asBlock(V[N]));
      I = B;
      break;
    }
    case Instruction::Call:
    case Instruction::Invoke:
    case Instruction::CallBr:
      I = decodeCall(Op, F, D, V, Block);
      break;
    case Instruction::Resume:
      Arity(1);
      I = ResumeInst::Create(V[0], Block);
      break;
    case Instruction::Unreachable:
      Arity(0);
      I = new UnreachableInst(D.context(), Block);
      break;
    case Instruction::Alloca: {
      Arity(1);
      if (!V[0]->getType()->isIntegerTy())
        fail("alloca size is not an integer");
      Type *Allocated = D.type(F.get("allocated_type"));
      unsigned AddressSpace = F.count("address_space");
      if (AddressSpace > 0xffffff)
        fail("alloca address space exceeds LLVM pointer representation");
      auto *X = new AllocaInst(Allocated, AddressSpace, V[0],
                               alignment(F), "", Block);
      X->setUsedWithInAlloca(F.boolean("inalloca"));
      X->setSwiftError(F.boolean("swifterror"));
      I = X;
      break;
    }
    case Instruction::Load: {
      Arity(1);
      requirePointer(V[0]);
      AtomicOrdering Order = ordering(F, "ordering");
      if (Order == AtomicOrdering::Release ||
          Order == AtomicOrdering::AcquireRelease)
        fail("invalid load ordering");
      I = new LoadInst(ResultType, V[0], "", F.boolean("volatile"),
                        alignment(F), Order, syncScope(F, D), Block);
      break;
    }
    case Instruction::Store: {
      Arity(2);
      requirePointer(V[1]);
      AtomicOrdering Order = ordering(F, "ordering");
      if (Order == AtomicOrdering::Acquire ||
          Order == AtomicOrdering::AcquireRelease)
        fail("invalid store ordering");
      I = new StoreInst(V[0], V[1], F.boolean("volatile"), alignment(F),
                         Order, syncScope(F, D), Block);
      break;
    }
    case Instruction::Fence: {
      Arity(0);
      AtomicOrdering Order = ordering(F, "ordering");
      if (Order != AtomicOrdering::Acquire &&
          Order != AtomicOrdering::Release &&
          Order != AtomicOrdering::AcquireRelease &&
          Order != AtomicOrdering::SequentiallyConsistent)
        fail("invalid fence ordering");
      I = new FenceInst(D.context(), Order, syncScope(F, D), Block);
      break;
    }
    case Instruction::AtomicCmpXchg: {
      Arity(3);
      requirePointer(V[0]);
      sameType(V[1], V[2]);
      AtomicOrdering Success = ordering(F, "success_ordering");
      AtomicOrdering Failure = ordering(F, "failure_ordering");
      if (!AtomicCmpXchgInst::isValidSuccessOrdering(Success) ||
          !AtomicCmpXchgInst::isValidFailureOrdering(Failure))
        fail("invalid cmpxchg ordering");
      auto *X = new AtomicCmpXchgInst(V[0], V[1], V[2], alignment(F),
                                      Success, Failure, syncScope(F, D), Block);
      X->setVolatile(F.boolean("volatile"));
      X->setWeak(F.boolean("weak"));
      I = X;
      break;
    }
    case Instruction::AtomicRMW: {
      Arity(2);
      requirePointer(V[0]);
      StringRef Name = F.str("operation");
      auto Operation = AtomicRMWInst::BAD_BINOP;
      for (unsigned N = AtomicRMWInst::FIRST_BINOP;
           N <= AtomicRMWInst::LAST_BINOP; ++N) {
        auto Candidate = static_cast<AtomicRMWInst::BinOp>(N);
        if (Name == AtomicRMWInst::getOperationName(Candidate)) {
          Operation = Candidate;
          break;
        }
      }
      if (Operation == AtomicRMWInst::BAD_BINOP)
        fail("unsupported atomicrmw operation");
      AtomicOrdering Order = ordering(F, "ordering");
      if (Order == AtomicOrdering::NotAtomic ||
          Order == AtomicOrdering::Unordered)
        fail("invalid atomicrmw ordering");
      auto *X = new AtomicRMWInst(Operation, V[0], V[1], alignment(F),
                                  Order, syncScope(F, D), Block);
      X->setVolatile(F.boolean("volatile"));
      I = X;
      break;
    }
    case Instruction::GetElementPtr: {
      if (V.empty()) fail("getelementptr has no base pointer");
      if (!V[0]->getType()->isPtrOrPtrVectorTy())
        fail("getelementptr requires a pointer or pointer vector");
      Type *Element = D.type(F.get("source_element_type"));
      ArrayRef<Value *> Indices = V.drop_front();
      for (Value *Index : Indices)
        if (!Index->getType()->isIntOrIntVectorTy())
          fail("getelementptr index is not integral");
      if (!GetElementPtrInst::getIndexedType(Element, Indices))
        fail("invalid getelementptr element/index types");
      bool InBounds = F.boolean("inbounds");
      bool NUSW = F.boolean("nusw");
      bool NUW = F.boolean("nuw");
      if (InBounds && !NUSW)
        fail("getelementptr inbounds requires nusw");
      GEPNoWrapFlags Flags = GEPNoWrapFlags::none();
      if (InBounds) Flags |= GEPNoWrapFlags::inBounds();
      if (NUSW) Flags |= GEPNoWrapFlags::noUnsignedSignedWrap();
      if (NUW) Flags |= GEPNoWrapFlags::noUnsignedWrap();
      I = GetElementPtrInst::Create(Element, V[0], Indices, Flags, "", Block);
      break;
    }
    case Instruction::ICmp:
    case Instruction::FCmp: {
      Arity(2);
      sameType(V[0], V[1]);
      bool IsInt = Op == Instruction::ICmp;
      Type *T = V[0]->getType();
      if (IsInt ? !(T->isIntOrIntVectorTy() || T->isPtrOrPtrVectorTy())
                : !T->isFPOrFPVectorTy())
        fail("comparison has invalid operand types");
      auto P = predicate(F, IsInt);
      I = IsInt ? static_cast<Instruction *>(new ICmpInst(Block, P, V[0], V[1]))
                : static_cast<Instruction *>(new FCmpInst(Block, P, V[0], V[1]));
      break;
    }
    case Instruction::PHI: {
      const A &Blocks = F.array("incoming_blocks");
      if (Blocks.size() != V.size() || ResultType->isTokenTy() ||
          !ResultType->isFirstClassType())
        fail("invalid phi incoming layout or type");
      auto *P = PHINode::Create(ResultType, unsigned(V.size()), "", Block);
      for (size_t N = 0; N < V.size(); ++N) {
        if (V[N]->getType() != ResultType)
          fail("phi incoming value type mismatch");
        P->addIncoming(V[N], asBlock(D.value(Blocks[N])));
      }
      I = P;
      break;
    }
    case Instruction::Select:
      Arity(3);
      if (const char *Error = SelectInst::areInvalidOperands(V[0], V[1], V[2]))
        fail(Twine("invalid select: ") + Error);
      I = SelectInst::Create(V[0], V[1], V[2], "", Block);
      break;
    case Instruction::VAArg:
      Arity(1);
      requirePointer(V[0]);
      I = new VAArgInst(V[0], ResultType, "", Block);
      break;
    case Instruction::ExtractElement:
      Arity(2);
      if (!ExtractElementInst::isValidOperands(V[0], V[1]))
        fail("invalid extractelement operands");
      I = ExtractElementInst::Create(V[0], V[1], "", Block);
      break;
    case Instruction::InsertElement:
      Arity(3);
      if (!InsertElementInst::isValidOperands(V[0], V[1], V[2]))
        fail("invalid insertelement operands");
      I = InsertElementInst::Create(V[0], V[1], V[2], "", Block);
      break;
    case Instruction::ShuffleVector: {
      Arity(2);
      std::vector<int> Mask;
      for (const J &Entry : F.array("mask")) {
        auto N = Entry.getAsInteger();
        if (!N || *N < -1 || *N > std::numeric_limits<int>::max())
          fail("invalid shuffle mask entry");
        Mask.push_back(int(*N));
      }
      if (!ShuffleVectorInst::isValidOperands(V[0], V[1], Mask))
        fail("invalid shuffle vector operands or mask");
      I = new ShuffleVectorInst(V[0], V[1], Mask, "", Block);
      break;
    }
    case Instruction::ExtractValue: {
      Arity(1);
      auto Indices = indices(F);
      if (!ExtractValueInst::getIndexedType(V[0]->getType(), Indices))
        fail("invalid extractvalue indices");
      I = ExtractValueInst::Create(V[0], Indices, "", Block);
      break;
    }
    case Instruction::InsertValue: {
      Arity(2);
      auto Indices = indices(F);
      if (ExtractValueInst::getIndexedType(V[0]->getType(), Indices) !=
          V[1]->getType())
        fail("invalid insertvalue indices or inserted type");
      I = InsertValueInst::Create(V[0], V[1], Indices, "", Block);
      break;
    }
    case Instruction::LandingPad: {
      auto *P = LandingPadInst::Create(ResultType, unsigned(V.size()),
                                       "", Block);
      P->setCleanup(F.boolean("cleanup"));
      for (Value *Clause : V) {
        auto *C = dyn_cast<Constant>(Clause);
        if (!C) fail("landingpad clause is not a constant");
        P->addClause(C);
      }
      I = P;
      break;
    }
    case Instruction::CatchSwitch: {
      bool Unwind = F.boolean("has_unwind");
      size_t First = Unwind ? 2 : 1;
      if (V.size() < First || !V[0]->getType()->isTokenTy())
        fail("invalid catchswitch operand layout");
      auto *C = CatchSwitchInst::Create(V[0],
          Unwind ? asBlock(V[1]) : nullptr, unsigned(V.size() - First), "", Block);
      for (size_t N = First; N < V.size(); ++N)
        C->addHandler(asBlock(V[N]));
      I = C;
      break;
    }
    case Instruction::CleanupPad:
    case Instruction::CatchPad:
      if (V.empty() || !V.back()->getType()->isTokenTy())
        fail("funclet pad has no parent token");
      I = Op == Instruction::CleanupPad
              ? static_cast<Instruction *>(CleanupPadInst::Create(
                    V.back(), V.drop_back(), "", Block))
              : static_cast<Instruction *>(CatchPadInst::Create(
                    V.back(), V.drop_back(), "", Block));
      break;
    case Instruction::CatchRet:
      Arity(2);
      if (!V[0]->getType()->isTokenTy()) fail("catchret requires a pad token");
      I = CatchReturnInst::Create(V[0], asBlock(V[1]), Block);
      break;
    case Instruction::CleanupRet:
      if (V.empty() || V.size() > 2 || !V[0]->getType()->isTokenTy())
        fail("invalid cleanupret operands");
      I = CleanupReturnInst::Create(V[0],
                                    V.size() == 2 ? asBlock(V[1]) : nullptr, Block);
      break;
    case Instruction::Freeze:
      Arity(1);
      I = new FreezeInst(V[0], "", Block);
      break;
    default:
      fail(Twine("no typed constructor for opcode: ") +
           Instruction::getOpcodeName(Op));
    }
  }

  if (!I || I->getType() != ResultType)
    fail("reconstructed instruction result type disagrees with HIA type");
  decodeFlags(F, *I);
  F.finish(true);
  return I;
}
} // namespace hia
