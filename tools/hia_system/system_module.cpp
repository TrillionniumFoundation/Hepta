// Copyright (c) Hepta contributors. SPDX-License-Identifier: MIT
// Structured, explicitly unsafe systems dialect. No LLVM text parser is used
// during decode: every Type, Value, Constant and Instruction is built anew.
#include "system_wire.h"
#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalIFunc.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/TrackingMDRef.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#if LLVM_VERSION_MAJOR != 20
#error "hepta.hia.system.v1 requires LLVM 20"
#endif

namespace hia {
using namespace llvm;

[[noreturn]] void fail(const Twine &Message) {
  errs() << "HIA_SYSTEM_REJECT: " << Message << '\n';
  std::exit(1);
}

namespace {
const O &obj(const J &V) {
  auto *R = V.getAsObject();
  if (!R) fail("expected object");
  return *R;
}
const A &arr(const J &V) {
  auto *R = V.getAsArray();
  if (!R) fail("expected array");
  return *R;
}
const J &req(const O &V, StringRef Key) {
  auto *R = V.get(Key);
  if (!R) fail(Twine("missing field: ") + Key);
  return *R;
}
std::string str(const J &V) {
  auto R = V.getAsString();
  if (!R) fail("expected string");
  return R->str();
}
std::string str(const O &V, StringRef Key) { return str(req(V, Key)); }
bool boolean(const J &V) {
  auto R = V.getAsBoolean();
  if (!R) fail("expected boolean");
  return *R;
}
bool boolean(const O &V, StringRef Key) { return boolean(req(V, Key)); }
uint64_t uint(const J &V, uint64_t Max = UINT64_MAX) {
  auto R = V.getAsInteger();
  if (!R || *R < 0 || uint64_t(*R) > Max) fail("invalid unsigned integer");
  return uint64_t(*R);
}
uint64_t uint(const O &V, StringRef Key, uint64_t Max = UINT64_MAX) {
  return uint(req(V, Key), Max);
}
uint64_t decimal(const J &V) {
  uint64_t R;
  auto S = str(V);
  if (S.empty() || StringRef(S).getAsInteger(10, R))
    fail("invalid unsigned decimal string");
  return R;
}
void keys(const O &V, std::initializer_list<StringRef> Allowed) {
  for (auto &KV : V) {
    bool Found = false;
    for (auto K : Allowed) if (StringRef(KV.first) == K) Found = true;
    if (!Found) fail(Twine("unknown field: ") + StringRef(KV.first));
  }
}
std::string bits(const APInt &V) {
  SmallString<80> S;
  V.toString(S, 16, false);
  return S.str().str();
}
APInt readBits(unsigned Width, const J &V) {
  auto S = str(V);
  if (!Width || Width > (1U << 23) || S.empty() ||
      S.size() > (Width + 3ULL) / 4)
    fail("invalid APInt width or hexadecimal length");
  for (char C : S)
    if (!((C >= '0' && C <= '9') || (C >= 'a' && C <= 'f') ||
          (C >= 'A' && C <= 'F')))
      fail("invalid hexadecimal integer");
  APInt Wide(std::max<unsigned>(Width, S.size() * 4), S, 16);
  if (Wide.getActiveBits() > Width) fail("integer bits exceed declared width");
  return Wide.zextOrTrunc(Width);
}
std::string hex(StringRef Bytes) {
  static const char *Digits = "0123456789abcdef";
  std::string R;
  R.reserve(Bytes.size() * 2);
  for (unsigned char C : Bytes) {
    R.push_back(Digits[C >> 4]); R.push_back(Digits[C & 15]);
  }
  return R;
}
std::string unhex(const J &V) {
  auto S = str(V);
  if (S.size() % 2) fail("odd byte string length");
  auto Nibble = [](char C) -> unsigned {
    if (C >= '0' && C <= '9') return C - '0';
    if (C >= 'a' && C <= 'f') return C - 'a' + 10;
    if (C >= 'A' && C <= 'F') return C - 'A' + 10;
    fail("invalid byte string");
  };
  std::string R;
  R.reserve(S.size() / 2);
  for (size_t I = 0; I < S.size(); I += 2)
    R.push_back(char((Nibble(S[I]) << 4) | Nibble(S[I + 1])));
  return R;
}
J range(const ConstantRange &R) {
  return O{{"bits", int64_t(R.getBitWidth())},
           {"lower", bits(R.getLower())}, {"upper", bits(R.getUpper())}};
}
ConstantRange readRange(const J &V) {
  auto &O = obj(V);
  keys(O, {"bits", "lower", "upper"});
  unsigned W = uint(O, "bits", 1U << 23);
  return ConstantRange(readBits(W, req(O, "lower")),
                       readBits(W, req(O, "upper")));
}
template<class T> T *need(Value *V, StringRef Kind) {
  auto *R = dyn_cast_or_null<T>(V);
  if (!R) fail(Twine("expected ") + Kind);
  return R;
}
template<class T> T *needTy(Type *V, StringRef Kind) {
  auto *R = dyn_cast_or_null<T>(V);
  if (!R) fail(Twine("expected type ") + Kind);
  return R;
}
unsigned opcode(StringRef Name) {
  for (unsigned I = 1; I < Instruction::OtherOpsEnd; ++I)
    if (Name == Instruction::getOpcodeName(I)) return I;
  fail(Twine("unknown opcode: ") + Name);
}
} // namespace

struct Encoder::Impl {
  const Module &M;
  std::map<const Type *, std::string> Types;
  std::map<const Value *, std::string> Values;
  std::map<const Metadata *, std::string> MDs;
  A TypeDefs, MDDefs;
  explicit Impl(const Module &M) : M(M) {}
  void add(const Value *V) {
    if (!Values.count(V)) Values[V] = "v" + std::to_string(Values.size());
  }
};

Encoder::Encoder(const Module &M) : P(new Impl(M)) {
  for (auto &G : M.globals()) P->add(&G);
  for (auto &G : M.aliases()) P->add(&G);
  for (auto &G : M.ifuncs()) P->add(&G);
  for (auto &F : M) {
    P->add(&F);
    for (auto &Arg : F.args()) P->add(&Arg);
    for (auto &B : F) {
      P->add(&B);
      for (auto &I : B) P->add(&I);
    }
  }
}
Encoder::~Encoder() = default;

J Encoder::type(const Type *T) {
  auto It = P->Types.find(T);
  if (It != P->Types.end()) return It->second;
  size_t Slot = P->TypeDefs.size();
  std::string ID = "t" + std::to_string(Slot);
  P->Types[T] = ID;
  P->TypeDefs.push_back(nullptr);
  O R{{"id", ID}};
  switch (T->getTypeID()) {
#define SCALAR(ID, NAME) case Type::ID: R["kind"] = NAME; break;
    SCALAR(VoidTyID, "void")
    SCALAR(LabelTyID, "label")
    SCALAR(MetadataTyID, "metadata")
    SCALAR(TokenTyID, "token")
    SCALAR(HalfTyID, "half")
    SCALAR(BFloatTyID, "bfloat")
    SCALAR(FloatTyID, "float")
    SCALAR(DoubleTyID, "double")
    SCALAR(X86_FP80TyID, "x86_fp80")
    SCALAR(FP128TyID, "fp128")
    SCALAR(PPC_FP128TyID, "ppc_fp128")
    SCALAR(X86_AMXTyID, "x86_amx")
#undef SCALAR
  case Type::IntegerTyID:
    R["kind"] = "integer";
    R["bits"] = int64_t(cast<IntegerType>(T)->getBitWidth());
    break;
  case Type::PointerTyID:
    R["kind"] = "pointer";
    R["address_space"] = int64_t(cast<PointerType>(T)->getAddressSpace());
    break;
  case Type::FunctionTyID: {
    auto *FT = cast<FunctionType>(T);
    R["kind"] = "function";
    R["return"] = type(FT->getReturnType());
    R["vararg"] = FT->isVarArg();
    A Args;
    for (auto *A : FT->params()) Args.push_back(type(A));
    R["parameters"] = std::move(Args);
    break;
  }
  case Type::StructTyID: {
    auto *ST = cast<StructType>(T);
    R["kind"] = "struct";
    R["literal"] = ST->isLiteral();
    R["name"] = ST->hasName() ? ST->getName().str() : "";
    R["opaque"] = ST->isOpaque();
    R["packed"] = ST->isPacked();
    A Elems;
    if (!ST->isOpaque())
      for (auto *E : ST->elements()) Elems.push_back(type(E));
    R["elements"] = std::move(Elems);
    break;
  }
  case Type::ArrayTyID: {
    auto *AT = cast<ArrayType>(T);
    R["kind"] = "array";
    R["count"] = std::to_string(AT->getNumElements());
    R["element"] = type(AT->getElementType());
    break;
  }
  case Type::FixedVectorTyID:
  case Type::ScalableVectorTyID: {
    auto *VT = cast<VectorType>(T);
    R["kind"] = "vector";
    R["count"] = int64_t(VT->getElementCount().getKnownMinValue());
    R["scalable"] = VT->getElementCount().isScalable();
    R["element"] = type(VT->getElementType());
    break;
  }
  case Type::TargetExtTyID: {
    auto *TT = cast<TargetExtType>(T);
    R["kind"] = "target_extension";
    R["name"] = TT->getName().str();
    A TP, IP;
    for (auto *T : TT->type_params()) TP.push_back(type(T));
    for (auto I : TT->int_params()) IP.push_back(int64_t(I));
    R["type_parameters"] = std::move(TP);
    R["integer_parameters"] = std::move(IP);
    break;
  }
  default: fail("unsupported LLVM type kind");
  }
  P->TypeDefs[Slot] = std::move(R);
  return ID;
}

J Encoder::value(const Value *V) {
  if (!V) return nullptr;
  auto It = P->Values.find(V);
  if (It != P->Values.end())
    return O{{"kind", "ref"}, {"id", It->second}, {"type", type(V->getType())}};
  O R{{"type", type(V->getType())}};
  if (auto *IA = dyn_cast<InlineAsm>(V)) {
    R["kind"] = "inline_asm";
    R["function_type"] = type(IA->getFunctionType());
    R["assembly_hex"] = hex(IA->getAsmString());
    R["constraints"] = IA->getConstraintString();
    R["side_effects"] = IA->hasSideEffects();
    R["align_stack"] = IA->isAlignStack();
    R["dialect"] = int64_t(IA->getDialect());
    R["can_throw"] = IA->canThrow();
  } else if (auto *MV = dyn_cast<MetadataAsValue>(V)) {
    R["kind"] = "metadata";
    R["metadata"] = metadata(MV->getMetadata());
  } else if (auto *CI = dyn_cast<ConstantInt>(V)) {
    R["kind"] = "integer"; R["hex"] = bits(CI->getValue());
  } else if (auto *CF = dyn_cast<ConstantFP>(V)) {
    R["kind"] = "float"; R["hex"] = bits(CF->getValueAPF().bitcastToAPInt());
  } else if (isa<PoisonValue>(V)) {
    R["kind"] = "poison";
  } else if (isa<UndefValue>(V)) {
    R["kind"] = "undef";
  } else if (isa<ConstantPointerNull>(V)) {
    R["kind"] = "null";
  } else if (isa<ConstantAggregateZero>(V)) {
    R["kind"] = "zero";
  } else if (isa<ConstantTokenNone>(V)) {
    R["kind"] = "token_none";
  } else if (isa<ConstantTargetNone>(V)) {
    R["kind"] = "target_none";
  } else if (auto *BA = dyn_cast<BlockAddress>(V)) {
    R["kind"] = "block_address";
    R["function"] = value(BA->getFunction());
    R["block"] = value(BA->getBasicBlock());
  } else if (auto *DS = dyn_cast<DSOLocalEquivalent>(V)) {
    R["kind"] = "dso_local_equivalent";
    R["global"] = value(DS->getGlobalValue());
  } else if (auto *NC = dyn_cast<NoCFIValue>(V)) {
    R["kind"] = "no_cfi";
    R["global"] = value(NC->getGlobalValue());
  } else if (auto *PA = dyn_cast<ConstantPtrAuth>(V)) {
    R["kind"] = "pointer_auth";
    R["pointer"] = value(PA->getPointer());
    R["key"] = value(PA->getKey());
    R["discriminator"] = value(PA->getDiscriminator());
    R["address_discriminator"] = value(PA->getAddrDiscriminator());
  } else if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    R["kind"] = "expression";
    R["op"] = Instruction::getOpcodeName(CE->getOpcode());
    A Operands;
    for (auto &Op : CE->operands()) Operands.push_back(value(Op.get()));
    R["operands"] = std::move(Operands);
    unsigned Flags = 0;
    if (auto *OB = dyn_cast<OverflowingBinaryOperator>(CE))
      Flags = OB->getNoWrapKind();
    if (auto *EX = dyn_cast<PossiblyExactOperator>(CE))
      Flags = EX->isExact() ? PossiblyExactOperator::IsExact : 0;
    if (CE->getOpcode() != Instruction::GetElementPtr &&
        CE->getRawSubclassOptionalData() != Flags)
      fail("unrepresented constant-expression flags");
    R["flags"] = int64_t(Flags);
    if (auto *GE = dyn_cast<GEPOperator>(CE)) {
      R["source_element"] = type(GE->getSourceElementType());
      R["gep_no_wrap"] = int64_t(GE->getNoWrapFlags().getRaw());
      R["in_range"] = GE->getInRange() ? range(*GE->getInRange()) : J(nullptr);
    }
    if (CE->getOpcode() == Instruction::ShuffleVector) {
      A Mask;
      for (int M : CE->getShuffleMask()) Mask.push_back(int64_t(M));
      R["shuffle_mask"] = std::move(Mask);
    }
  } else if (auto *Bytes = dyn_cast<ConstantDataArray>(V);
             Bytes && Bytes->getElementType()->isIntegerTy(8)) {
    R["kind"] = "bytes"; R["hex"] = hex(Bytes->getAsString());
  } else if (auto *CD = dyn_cast<ConstantDataSequential>(V)) {
    R["kind"] = "aggregate";
    A Elements;
    for (unsigned I = 0; I < CD->getNumElements(); ++I)
      Elements.push_back(value(CD->getElementAsConstant(I)));
    R["elements"] = std::move(Elements);
  } else if (isa<ConstantArray>(V) || isa<ConstantStruct>(V) ||
             isa<ConstantVector>(V)) {
    R["kind"] = "aggregate";
    A Elements;
    for (auto &Op : cast<Constant>(V)->operands())
      Elements.push_back(value(Op.get()));
    R["elements"] = std::move(Elements);
  } else {
    fail(Twine("unregistered value or unsupported constant kind: ") +
         Twine(V->getValueID()));
  }
  return R;
}

J Encoder::attributes(const AttributeList &List) {
  A R;
  for (unsigned Index : List.indexes()) {
    auto Set = List.getAttributes(Index);
    if (!Set.hasAttributes()) continue;
    A Attrs;
    for (auto Attr : Set) {
      O E;
      if (Attr.isStringAttribute()) {
        E["kind"] = "string";
        E["name"] = Attr.getKindAsString().str();
        E["value_hex"] = hex(Attr.getValueAsString());
      } else {
        auto Kind = Attr.getKindAsEnum();
        E["name"] = Attribute::getNameFromAttrKind(Kind).str();
        if (Attr.isEnumAttribute()) {
          E["kind"] = "enum";
        } else if (Attr.isIntAttribute()) {
          E["kind"] = "integer";
          E["value"] = std::to_string(Attr.getValueAsInt());
        } else if (Attr.isTypeAttribute()) {
          E["kind"] = "type";
          E["type"] = type(Attr.getValueAsType());
        } else if (Attr.isConstantRangeAttribute()) {
          E["kind"] = "range";
          E["range"] = range(Attr.getValueAsConstantRange());
        } else if (Attr.isConstantRangeListAttribute()) {
          E["kind"] = "range_list";
          A Ranges;
          for (auto &CR : Attr.getValueAsConstantRangeList())
            Ranges.push_back(range(CR));
          E["ranges"] = std::move(Ranges);
        } else fail("unknown attribute category");
      }
      Attrs.push_back(std::move(E));
    }
    R.push_back(O{{"index", int64_t(Index)}, {"attributes", std::move(Attrs)}});
  }
  return R;
}

J Encoder::metadata(const Metadata *MD) {
  if (!MD) return nullptr;
  auto It = P->MDs.find(MD);
  if (It != P->MDs.end()) return It->second;
  size_t Slot = P->MDDefs.size();
  std::string ID = "m" + std::to_string(Slot);
  P->MDs[MD] = ID;
  P->MDDefs.push_back(nullptr);
  O R{{"id", ID}};
  if (auto *S = dyn_cast<MDString>(MD)) {
    R["kind"] = "string"; R["hex"] = hex(S->getString());
  } else if (auto *V = dyn_cast<ConstantAsMetadata>(MD)) {
    R["kind"] = "constant"; R["value"] = value(V->getValue());
  } else if (auto *V = dyn_cast<LocalAsMetadata>(MD)) {
    R["kind"] = "local"; R["value"] = value(V->getValue());
  } else if (auto *N = dyn_cast<MDTuple>(MD)) {
    if (N->isTemporary()) fail("temporary metadata in encoded module");
    R["kind"] = "tuple"; R["distinct"] = N->isDistinct();
    A Ops;
    for (auto &Op : N->operands()) Ops.push_back(metadata(Op.get()));
    R["operands"] = std::move(Ops);
  } else {
    fail(Twine("unsupported specialized metadata kind: ") +
         Twine(MD->getMetadataID()) +
         "; debug records and DI nodes must not be silently stripped");
  }
  P->MDDefs[Slot] = std::move(R);
  return ID;
}

struct Decoder::Impl {
  LLVMContext &C;
  Module &M;
  std::map<std::string, const O *> TypeDefs, MDDefs;
  std::map<std::string, Type *> Types;
  std::set<std::string> ActiveTypes;
  std::map<std::string, Value *> Values;
  std::map<std::string, std::unique_ptr<Argument>> Pending;
  std::map<std::string, TrackingMDRef> MDs;
  explicit Impl(LLVMContext &C, Module &M) : C(C), M(M) {}
};
Decoder::Decoder(LLVMContext &C, Module &M) : P(new Impl(C, M)) {}
Decoder::~Decoder() = default;
LLVMContext &Decoder::context() { return P->C; }
Module &Decoder::module() { return P->M; }

Type *Decoder::type(const J &V) {
  auto ID = str(V);
  auto Have = P->Types.find(ID);
  if (Have != P->Types.end()) return Have->second;
  auto Def = P->TypeDefs.find(ID);
  if (Def == P->TypeDefs.end()) fail(Twine("undefined type: ") + ID);
  if (!P->ActiveTypes.insert(ID).second)
    fail("type recursion without an identified structure");
  const O &O = *Def->second;
  auto K = str(O, "kind");
  Type *T = nullptr;
#define SCALAR(NAME, FN) if (K == NAME) { keys(O, {"id", "kind"}); T = Type::FN(P->C); } else
  SCALAR("void", getVoidTy)
  SCALAR("label", getLabelTy)
  SCALAR("metadata", getMetadataTy)
  SCALAR("token", getTokenTy)
  SCALAR("half", getHalfTy)
  SCALAR("bfloat", getBFloatTy)
  SCALAR("float", getFloatTy)
  SCALAR("double", getDoubleTy)
  SCALAR("x86_fp80", getX86_FP80Ty)
  SCALAR("fp128", getFP128Ty)
  SCALAR("ppc_fp128", getPPC_FP128Ty)
  SCALAR("x86_amx", getX86_AMXTy)
#undef SCALAR
  if (K == "integer") {
    keys(O, {"id", "kind", "bits"});
    unsigned W = uint(O, "bits", IntegerType::MAX_INT_BITS);
    if (!W) fail("zero-width integer");
    T = IntegerType::get(P->C, W);
  } else if (K == "pointer") {
    keys(O, {"id", "kind", "address_space"});
    T = PointerType::get(P->C, uint(O, "address_space", 0xffffff));
  } else if (K == "function") {
    keys(O, {"id", "kind", "return", "parameters", "vararg"});
    std::vector<Type *> Args;
    auto *Ret = type(req(O, "return"));
    if (!FunctionType::isValidReturnType(Ret)) fail("invalid function return type");
    for (auto &A : arr(req(O, "parameters"))) {
      auto *PT = type(A);
      if (!FunctionType::isValidArgumentType(PT)) fail("invalid parameter type");
      Args.push_back(PT);
    }
    T = FunctionType::get(Ret, Args, boolean(O, "vararg"));
  } else if (K == "struct") {
    keys(O, {"id", "kind", "literal", "name", "opaque", "packed", "elements"});
    if (!boolean(O, "literal")) fail("identified type skeleton missing");
    if (boolean(O, "opaque") || !str(O, "name").empty())
      fail("literal struct cannot be opaque or named");
    std::vector<Type *> Elems;
    for (auto &E : arr(req(O, "elements"))) {
      auto *ET = type(E);
      if (!StructType::isValidElementType(ET)) fail("invalid struct element");
      Elems.push_back(ET);
    }
    T = StructType::get(P->C, Elems, boolean(O, "packed"));
  } else if (K == "array") {
    keys(O, {"id", "kind", "count", "element"});
    auto *ET = type(req(O, "element"));
    if (!ArrayType::isValidElementType(ET)) fail("invalid array element");
    T = ArrayType::get(ET, decimal(req(O, "count")));
  } else if (K == "vector") {
    keys(O, {"id", "kind", "count", "scalable", "element"});
    auto *ET = type(req(O, "element"));
    unsigned Count = uint(O, "count", UINT32_MAX);
    if (!Count || !VectorType::isValidElementType(ET)) fail("invalid vector type");
    T = VectorType::get(ET, ElementCount::get(Count, boolean(O, "scalable")));
  } else if (K == "target_extension") {
    keys(O, {"id", "kind", "name", "type_parameters", "integer_parameters"});
    std::vector<Type *> TP;
    std::vector<unsigned> IP;
    for (auto &P : arr(req(O, "type_parameters"))) TP.push_back(type(P));
    for (auto &P : arr(req(O, "integer_parameters"))) IP.push_back(uint(P, UINT32_MAX));
    T = TargetExtType::get(P->C, str(O, "name"), TP, IP);
  } else fail(Twine("unknown type kind: ") + K);
  P->Types[ID] = T;
  P->ActiveTypes.erase(ID);
  return T;
}

void Decoder::bind(const std::string &ID, Value *V) {
  if (ID.empty() || !V) fail("invalid value binding");
  auto It = P->Values.find(ID);
  if (It != P->Values.end()) {
    auto Pending = P->Pending.find(ID);
    if (Pending == P->Pending.end()) fail(Twine("duplicate value ID: ") + ID);
    if (It->second->getType() != V->getType()) fail("forward value type mismatch");
    Pending->second->replaceAllUsesWith(V);
    It->second = V;
    P->Pending.erase(Pending);
  } else P->Values[ID] = V;
}

Value *Decoder::value(const J &V) {
  if (V.kind() == J::Null) return nullptr;
  auto &O = obj(V);
  auto K = str(O, "kind");
  auto *T = type(req(O, "type"));
  Value *R = nullptr;
  auto CV = [&](const J &N) { return need<Constant>(value(N), "constant"); };
  if (K == "ref") {
    keys(O, {"kind", "id", "type"});
    auto ID = str(O, "id");
    auto It = P->Values.find(ID);
    if (It != P->Values.end()) {
      if (It->second->getType() != T) fail("reference type mismatch");
      return It->second;
    }
    if (T->isVoidTy() || T->isLabelTy() || T->isMetadataTy())
      fail("unbound reference has forbidden forward type");
    auto Placeholder = std::make_unique<Argument>(T);
    R = Placeholder.get();
    P->Pending[ID] = std::move(Placeholder);
    P->Values[ID] = R;
    return R;
  } else if (K == "inline_asm") {
    keys(O, {"kind", "type", "function_type", "assembly_hex", "constraints",
             "side_effects", "align_stack", "dialect", "can_throw"});
    auto *FT = needTy<FunctionType>(type(req(O, "function_type")), "function");
    auto Constraints = str(O, "constraints");
    if (auto Error = InlineAsm::verify(FT, Constraints))
      fail(Twine("invalid inline asm constraints: ") + toString(std::move(Error)));
    R = InlineAsm::get(FT, unhex(req(O, "assembly_hex")), Constraints,
                       boolean(O, "side_effects"), boolean(O, "align_stack"),
                       InlineAsm::AsmDialect(uint(O, "dialect", 1)),
                       boolean(O, "can_throw"));
  } else if (K == "metadata") {
    keys(O, {"kind", "type", "metadata"});
    auto *MD = metadata(req(O, "metadata"));
    if (!MD) fail("null MetadataAsValue");
    R = MetadataAsValue::get(P->C, MD);
  } else if (K == "integer") {
    keys(O, {"kind", "type", "hex"});
    auto *IT = needTy<IntegerType>(T, "integer");
    R = ConstantInt::get(P->C, readBits(IT->getBitWidth(), req(O, "hex")));
  } else if (K == "float") {
    keys(O, {"kind", "type", "hex"});
    if (!T->isFloatingPointTy()) fail("floating constant has non-float type");
    unsigned Width = APFloat::semanticsSizeInBits(T->getFltSemantics());
    APFloat F(T->getFltSemantics(), readBits(Width, req(O, "hex")));
    R = ConstantFP::get(P->C, F);
  } else if (K == "poison" || K == "undef" || K == "zero" ||
             K == "null" || K == "token_none" || K == "target_none") {
    keys(O, {"kind", "type"});
    if (K == "poison") R = PoisonValue::get(T);
    else if (K == "undef") R = UndefValue::get(T);
    else if (K == "zero") {
      if (!T->isAggregateType() && !T->isVectorTy()) fail("non-aggregate zero");
      R = ConstantAggregateZero::get(T);
    } else if (K == "null")
      R = ConstantPointerNull::get(needTy<PointerType>(T, "pointer"));
    else if (K == "target_none")
      R = ConstantTargetNone::get(needTy<TargetExtType>(T, "target extension"));
    else R = ConstantTokenNone::get(P->C);
  } else if (K == "block_address") {
    keys(O, {"kind", "type", "function", "block"});
    auto *F = need<Function>(value(req(O, "function")), "function");
    auto *B = need<BasicBlock>(value(req(O, "block")), "basic block");
    if (B->getParent() != F) fail("blockaddress parent mismatch");
    R = BlockAddress::get(F, B);
  } else if (K == "dso_local_equivalent" || K == "no_cfi") {
    keys(O, {"kind", "type", "global"});
    auto *G = need<GlobalValue>(value(req(O, "global")), "global");
    R = K == "no_cfi" ? static_cast<Constant *>(NoCFIValue::get(G)) :
                        static_cast<Constant *>(DSOLocalEquivalent::get(G));
  } else if (K == "pointer_auth") {
    keys(O, {"kind", "type", "pointer", "key", "discriminator", "address_discriminator"});
    R = ConstantPtrAuth::get(CV(req(O, "pointer")),
        need<ConstantInt>(value(req(O, "key")), "integer key"),
        need<ConstantInt>(value(req(O, "discriminator")), "integer discriminator"),
        CV(req(O, "address_discriminator")));
  } else if (K == "bytes") {
    keys(O, {"kind", "type", "hex"});
    auto *AT = needTy<ArrayType>(T, "byte array");
    auto Bytes = unhex(req(O, "hex"));
    if (!AT->getElementType()->isIntegerTy(8) || AT->getNumElements() != Bytes.size())
      fail("byte constant type or length mismatch");
    R = ConstantDataArray::getString(P->C, Bytes, false);
  } else if (K == "aggregate") {
    keys(O, {"kind", "type", "elements"});
    std::vector<Constant *> Es;
    for (auto &E : arr(req(O, "elements"))) Es.push_back(CV(E));
    if (auto *AT = dyn_cast<ArrayType>(T)) {
      if (AT->getNumElements() != Es.size()) fail("array constant length");
      for (auto *E : Es) if (E->getType() != AT->getElementType()) fail("array constant type");
      R = ConstantArray::get(AT, Es);
    } else if (auto *ST = dyn_cast<StructType>(T)) {
      if (ST->isOpaque() || ST->getNumElements() != Es.size()) fail("struct constant length");
      for (unsigned I = 0; I < Es.size(); ++I)
        if (Es[I]->getType() != ST->getElementType(I)) fail("struct constant type");
      R = ConstantStruct::get(ST, Es);
    } else if (auto *VT = dyn_cast<FixedVectorType>(T)) {
      if (VT->getNumElements() != Es.size()) fail("vector constant length");
      for (auto *E : Es) if (E->getType() != VT->getElementType()) fail("vector constant type");
      R = ConstantVector::get(Es);
    } else fail("unsupported aggregate constant type");
  } else if (K == "expression") {
    keys(O, {"kind", "type", "op", "operands", "flags", "source_element",
             "gep_no_wrap", "in_range", "shuffle_mask"});
    unsigned Op = opcode(str(O, "op"));
    if (Op == Instruction::GetElementPtr)
      keys(O, {"kind", "type", "op", "operands", "flags", "source_element",
               "gep_no_wrap", "in_range"});
    else if (Op == Instruction::ShuffleVector)
      keys(O, {"kind", "type", "op", "operands", "flags", "shuffle_mask"});
    else
      keys(O, {"kind", "type", "op", "operands", "flags"});
    unsigned Flags = uint(O, "flags", 3);
    std::vector<Constant *> Ops;
    for (auto &E : arr(req(O, "operands"))) Ops.push_back(CV(E));
    auto Count = [&](size_t N) { if (Ops.size() != N) fail("constant expression arity"); };
    if (Instruction::isCast(Op)) {
      Count(1);
      if (Flags) fail("unsupported constant cast flags");
      if (!ConstantExpr::isSupportedCastOp(Op)) fail("unsupported constant cast opcode");
      if (!CastInst::castIsValid(Instruction::CastOps(Op), Ops[0], T))
        fail("invalid constant cast");
      R = ConstantExpr::getCast(Op, Ops[0], T);
    } else if (Op == Instruction::GetElementPtr) {
      if (Ops.empty() || Flags) fail("invalid constant GEP");
      unsigned NW = uint(O, "gep_no_wrap", 7);
      if ((NW & 1) && !(NW & 2)) fail("inbounds requires nusw");
      std::optional<ConstantRange> Range;
      if (req(O, "in_range").kind() != J::Null)
        Range = readRange(req(O, "in_range"));
      R = ConstantExpr::getGetElementPtr(type(req(O, "source_element")), Ops[0],
          ArrayRef<Constant *>(Ops).drop_front(), GEPNoWrapFlags::fromRaw(NW), Range);
    } else if (Instruction::isBinaryOp(Op)) {
      Count(2);
      if (Ops[0]->getType() != Ops[1]->getType() ||
          !Ops[0]->getType()->isIntOrIntVectorTy())
        fail("constant binary operand types");
      if (!ConstantExpr::isSupportedBinOp(Op)) fail("unsupported constant binary opcode");
      if (Op == Instruction::Xor && Flags) fail("flags on constant xor");
      R = ConstantExpr::get(Op, Ops[0], Ops[1], Flags);
    } else if (Op == Instruction::ExtractElement) {
      Count(2); if (Flags) fail("extractelement flags");
      R = ConstantExpr::getExtractElement(Ops[0], Ops[1]);
    } else if (Op == Instruction::InsertElement) {
      Count(3); if (Flags) fail("insertelement flags");
      R = ConstantExpr::getInsertElement(Ops[0], Ops[1], Ops[2]);
    } else if (Op == Instruction::ShuffleVector) {
      Count(2); if (Flags) fail("shuffle flags");
      std::vector<int> Mask;
      for (auto &E : arr(req(O, "shuffle_mask"))) {
        auto N = E.getAsInteger();
        if (!N || *N < -1 || *N > INT32_MAX) fail("invalid shuffle mask");
        Mask.push_back(*N);
      }
      R = ConstantExpr::getShuffleVector(Ops[0], Ops[1], Mask);
    } else fail(Twine("unsupported constant expression: ") + str(O, "op"));
  } else fail(Twine("unknown value kind: ") + K);
  if (!R || R->getType() != T) fail("decoded value type differs from declared type");
  return R;
}

AttributeList Decoder::attributes(const J &V) {
  std::vector<std::pair<unsigned, AttributeSet>> Sets;
  std::set<unsigned> Indexes;
  for (auto &Entry : arr(V)) {
    auto &O = obj(Entry);
    keys(O, {"index", "attributes"});
    unsigned Index = uint(O, "index", UINT32_MAX);
    if (!Indexes.insert(Index).second) fail("duplicate attribute index");
    std::vector<Attribute> Attrs;
    std::set<std::string> Names;
    for (auto &AE : arr(req(O, "attributes"))) {
      auto &E = obj(AE);
      auto K = str(E, "kind");
      auto Name = str(E, "name");
      if (!Names.insert(Name).second) fail("duplicate attribute name");
      if (K == "string") {
        keys(E, {"kind", "name", "value_hex"});
        Attrs.push_back(Attribute::get(P->C, Name, unhex(req(E, "value_hex"))));
        continue;
      }
      auto Kind = Attribute::getAttrKindFromName(Name);
      if (Kind == Attribute::None) fail(Twine("unknown attribute: ") + Name);
      if (K == "enum") {
        keys(E, {"kind", "name"});
        if (!Attribute::isEnumAttrKind(Kind)) fail("attribute category mismatch");
        Attrs.push_back(Attribute::get(P->C, Kind));
      } else if (K == "integer") {
        keys(E, {"kind", "name", "value"});
        if (!Attribute::isIntAttrKind(Kind)) fail("attribute category mismatch");
        Attrs.push_back(Attribute::get(P->C, Kind, decimal(req(E, "value"))));
      } else if (K == "type") {
        keys(E, {"kind", "name", "type"});
        if (!Attribute::isTypeAttrKind(Kind)) fail("attribute category mismatch");
        Attrs.push_back(Attribute::get(P->C, Kind, type(req(E, "type"))));
      } else if (K == "range") {
        keys(E, {"kind", "name", "range"});
        if (!Attribute::isConstantRangeAttrKind(Kind)) fail("attribute category mismatch");
        Attrs.push_back(Attribute::get(P->C, Kind, readRange(req(E, "range"))));
      } else if (K == "range_list") {
        keys(E, {"kind", "name", "ranges"});
        if (!Attribute::isConstantRangeListAttrKind(Kind)) fail("attribute category mismatch");
        std::vector<ConstantRange> Ranges;
        for (auto &R : arr(req(E, "ranges"))) Ranges.push_back(readRange(R));
        Attrs.push_back(Attribute::get(P->C, Kind, Ranges));
      } else fail("unknown attribute category");
    }
    Sets.push_back({Index, AttributeSet::get(P->C, Attrs)});
  }
  return AttributeList::get(P->C, Sets);
}

Metadata *Decoder::metadata(const J &V) {
  if (V.kind() == J::Null) return nullptr;
  auto ID = str(V);
  auto It = P->MDs.find(ID);
  if (It != P->MDs.end()) return It->second.get();
  auto Def = P->MDDefs.find(ID);
  if (Def == P->MDDefs.end()) fail(Twine("undefined metadata: ") + ID);
  auto &O = *Def->second;
  auto K = str(O, "kind");
  Metadata *R = nullptr;
  if (K == "tuple") {
    keys(O, {"id", "kind", "distinct", "operands"});
    auto Temp = MDTuple::getTemporary(P->C, {});
    P->MDs.emplace(ID, TrackingMDRef(Temp.get()));
    std::vector<Metadata *> Ops;
    for (auto &E : arr(req(O, "operands"))) Ops.push_back(metadata(E));
    R = boolean(O, "distinct") ? MDTuple::getDistinct(P->C, Ops) :
                                MDTuple::get(P->C, Ops);
    TrackingMDRef Actual(R);
    Temp->replaceAllUsesWith(R);
    R = Actual.get();
    P->MDs[ID].reset(R);
  } else if (K == "string") {
    keys(O, {"id", "kind", "hex"});
    R = MDString::get(P->C, unhex(req(O, "hex")));
  } else if (K == "constant") {
    keys(O, {"id", "kind", "value"});
    R = ConstantAsMetadata::get(need<Constant>(value(req(O, "value")), "metadata constant"));
  } else if (K == "local") {
    keys(O, {"id", "kind", "value"});
    auto *LV = value(req(O, "value"));
    if (!LV || isa<Constant>(LV) || LV->getType()->isVoidTy())
      fail("invalid local metadata value");
    R = ValueAsMetadata::get(LV);
  } else fail(Twine("unknown metadata kind: ") + K);
  P->MDs[ID].reset(R);
  return R;
}

void Decoder::finish() {
  if (!P->Pending.empty()) fail(Twine("unresolved value: ") + P->Pending.begin()->first);
  // Read every descriptor, including otherwise unreferenced definitions.
  for (auto &E : P->TypeDefs) type(J(E.first));
  for (auto &E : P->MDDefs) metadata(J(E.first));
  if (!P->Pending.empty()) fail(Twine("unresolved metadata value: ") + P->Pending.begin()->first);
  for (auto &E : P->MDs) {
    if (auto *N = dyn_cast_or_null<MDNode>(E.second.get()))
      if (!N->isResolved()) N->resolveCycles();
  }
  if (verifyModule(P->M, &errs())) fail("LLVM verifier rejected reconstructed module");
}

namespace {
template<class T> J attachments(const T &V, Encoder &E) {
  SmallVector<std::pair<unsigned, MDNode *>, 8> Entries;
  V.getAllMetadata(Entries);
  SmallVector<StringRef, 32> Names;
  V.getContext().getMDKindNames(Names);
  A R;
  for (auto &Item : Entries) {
    if (Item.first >= Names.size()) fail("unregistered metadata kind");
    R.push_back(O{{"kind", Names[Item.first].str()},
                  {"node", E.metadata(Item.second)}});
  }
  return R;
}
J common(const GlobalValue &G, Encoder &E) {
  O R{{"linkage", int64_t(G.getLinkage())},
      {"visibility", int64_t(G.getVisibility())},
      {"dll_storage", int64_t(G.getDLLStorageClass())},
      {"unnamed_address", int64_t(G.getUnnamedAddr())},
      {"dso_local", G.isDSOLocal()},
      {"thread_local", int64_t(G.getThreadLocalMode())},
      {"partition", G.getPartition().str()},
      {"sanitizer", nullptr}};
  if (G.hasSanitizerMetadata()) {
    auto S = G.getSanitizerMetadata();
    R["sanitizer"] = O{{"no_address", bool(S.NoAddress)},
        {"no_hwaddress", bool(S.NoHWAddress)}, {"memtag", bool(S.Memtag)},
        {"dynamic_init", bool(S.IsDynInit)}};
  }
  return R;
}
J globalObject(const GlobalObject &G, Encoder &E) {
  return O{{"section", G.getSection().str()},
           {"alignment", std::to_string(G.getAlignment())},
           {"comdat", G.hasComdat() ? J(G.getComdat()->getName().str()) : J(nullptr)},
           {"metadata", attachments(G, E)}};
}
void setCommon(GlobalValue &G, const J &V) {
  auto &O = obj(V);
  keys(O, {"linkage", "visibility", "dll_storage", "unnamed_address",
           "dso_local", "thread_local", "partition", "sanitizer"});
  auto L = GlobalValue::LinkageTypes(uint(O, "linkage", GlobalValue::CommonLinkage));
  auto Vis = GlobalValue::VisibilityTypes(uint(O, "visibility", 2));
  auto DLL = GlobalValue::DLLStorageClassTypes(uint(O, "dll_storage", 2));
  if (GlobalValue::isLocalLinkage(L) && (Vis || DLL))
    fail("local linkage with nondefault visibility or DLL storage");
  G.setLinkage(L);
  G.setVisibility(Vis);
  G.setDLLStorageClass(DLL);
  G.setUnnamedAddr(GlobalValue::UnnamedAddr(uint(O, "unnamed_address", 2)));
  G.setDSOLocal(boolean(O, "dso_local"));
  auto TLS = GlobalValue::ThreadLocalMode(uint(O, "thread_local", 4));
  if (isa<Function>(G) && TLS != GlobalValue::NotThreadLocal)
    fail("thread-local function");
  G.setThreadLocalMode(TLS);
  G.setPartition(str(O, "partition"));
  auto &SV = req(O, "sanitizer");
  if (SV.kind() != J::Null) {
    if (!isa<GlobalVariable>(G)) fail("sanitizer metadata on non-variable");
    auto &S = obj(SV);
    keys(S, {"no_address", "no_hwaddress", "memtag", "dynamic_init"});
    GlobalValue::SanitizerMetadata SM;
    SM.NoAddress = boolean(S, "no_address");
    SM.NoHWAddress = boolean(S, "no_hwaddress");
    SM.Memtag = boolean(S, "memtag");
    SM.IsDynInit = boolean(S, "dynamic_init");
    G.setSanitizerMetadata(SM);
  }
}
void setGlobalObject(GlobalObject &G, const J &V, Decoder &D) {
  auto &O = obj(V);
  keys(O, {"section", "alignment", "comdat", "metadata"});
  G.setSection(str(O, "section"));
  uint64_t Align = decimal(req(O, "alignment"));
  if (Align && (!isPowerOf2_64(Align) || Align > Value::MaximumAlignment))
    fail("invalid global alignment");
  G.setAlignment(MaybeAlign(Align));
  auto &CD = req(O, "comdat");
  if (CD.kind() != J::Null) {
    auto Name = str(CD);
    auto &Table = D.module().getComdatSymbolTable();
    auto It = Table.find(Name);
    if (It == Table.end()) fail("undefined comdat");
    G.setComdat(&It->second);
  }
}
void setAttachments(GlobalObject &G, const J &V, Decoder &D) {
  for (auto &Item : arr(V)) {
    auto &O = obj(Item);
    keys(O, {"kind", "node"});
    auto *N = dyn_cast_or_null<MDNode>(D.metadata(req(O, "node")));
    if (!N) fail("global attachment must be a metadata node");
    G.addMetadata(G.getContext().getMDKindID(str(O, "kind")), *N);
  }
}
void setAttachments(Instruction &I, const J &V, Decoder &D) {
  std::set<std::string> Kinds;
  for (auto &Item : arr(V)) {
    auto &O = obj(Item);
    keys(O, {"kind", "node"});
    auto Name = str(O, "kind");
    if (!Kinds.insert(Name).second) fail("duplicate instruction metadata kind");
    auto *N = dyn_cast_or_null<MDNode>(D.metadata(req(O, "node")));
    if (!N) fail("instruction attachment must be a metadata node");
    I.setMetadata(I.getContext().getMDKindID(Name), N);
  }
}
GlobalValue::LinkageTypes linkage(const O &O) {
  return GlobalValue::LinkageTypes(uint(obj(req(O, "properties")), "linkage",
                                       GlobalValue::CommonLinkage));
}
unsigned addressSpace(const O &O) { return uint(O, "address_space", 0xffffff); }
Constant *constant(Decoder &D, const J &V) {
  return need<Constant>(D.value(V), "constant");
}
void noDebugRecords(const BasicBlock &B) {
  if (const_cast<BasicBlock &>(B).getTrailingDbgRecords())
    fail("trailing debug records are not yet represented in system.v1");
  for (auto &I : B)
    if (I.hasDbgRecords())
      fail("debug records are not yet represented in system.v1; refusing to drop them");
}
} // namespace

J encodeModule(const Module &M) {
  if (verifyModule(M, &errs())) fail("LLVM verifier rejected input module");
  Encoder E(M);
  O Root{{"schema", "hepta.hia.system.v1"},
         {"llvm_major", int64_t(20)},
         {"profile", "unsafe-systems-explicit-memory"}};
  Root["module"] = O{
      {"identifier", M.getModuleIdentifier()},
      {"source_filename", M.getSourceFileName()},
      {"target_triple", M.getTargetTriple()},
      {"data_layout", M.getDataLayoutStr()},
      {"inline_asm_hex", hex(M.getModuleInlineAsm())},
      {"new_debug_format", M.IsNewDbgInfoFormat}};
  A KindNames;
  SmallVector<StringRef, 32> Names;
  M.getContext().getMDKindNames(Names);
  for (auto N : Names) KindNames.push_back(N.str());
  Root["metadata_kind_names"] = std::move(KindNames);
  A Comdats;
  std::vector<const Comdat *> Sorted;
  for (auto &Entry : M.getComdatSymbolTable()) Sorted.push_back(&Entry.second);
  std::sort(Sorted.begin(), Sorted.end(),
      [](const Comdat *L, const Comdat *R) { return L->getName() < R->getName(); });
  for (auto *C : Sorted)
    Comdats.push_back(O{{"name", C->getName().str()},
                       {"selection", int64_t(C->getSelectionKind())}});
  Root["comdats"] = std::move(Comdats);
  A Globals, Aliases, IFuncs, Functions;
  for (auto &G : M.globals()) {
    O R{{"id", E.P->Values.at(&G)}, {"name", G.getName().str()},
        {"value_type", E.type(G.getValueType())},
        {"address_space", int64_t(G.getAddressSpace())},
        {"properties", common(G, E)}, {"object", globalObject(G, E)},
        {"constant", G.isConstant()}, {"externally_initialized", G.isExternallyInitialized()},
        {"initializer", G.hasInitializer() ? E.value(G.getInitializer()) : J(nullptr)},
        {"attributes", E.attributes(G.getAttributesAsList(AttributeList::FunctionIndex))},
        {"code_model", G.getCodeModel() ? J(int64_t(*G.getCodeModel())) : J(nullptr)}};
    Globals.push_back(std::move(R));
  }
  for (auto &G : M.aliases()) {
    Aliases.push_back(O{{"id", E.P->Values.at(&G)}, {"name", G.getName().str()},
        {"value_type", E.type(G.getValueType())},
        {"address_space", int64_t(G.getAddressSpace())},
        {"properties", common(G, E)}, {"aliasee", E.value(G.getAliasee())}});
  }
  for (auto &G : M.ifuncs()) {
    IFuncs.push_back(O{{"id", E.P->Values.at(&G)}, {"name", G.getName().str()},
        {"value_type", E.type(G.getValueType())},
        {"address_space", int64_t(G.getAddressSpace())},
        {"properties", common(G, E)}, {"object", globalObject(G, E)},
        {"resolver", E.value(G.getResolver())}});
  }
  for (auto &F : M) {
    O R{{"id", E.P->Values.at(&F)}, {"name", F.getName().str()},
        {"value_type", E.type(F.getFunctionType())},
        {"address_space", int64_t(F.getAddressSpace())},
        {"properties", common(F, E)}, {"object", globalObject(F, E)},
        {"calling_convention", int64_t(F.getCallingConv())},
        {"attributes", E.attributes(F.getAttributes())},
        {"gc", F.hasGC() ? J(F.getGC()) : J(nullptr)},
        {"personality", F.hasPersonalityFn() ? E.value(F.getPersonalityFn()) : J(nullptr)},
        {"prefix", F.hasPrefixData() ? E.value(F.getPrefixData()) : J(nullptr)},
        {"prologue", F.hasPrologueData() ? E.value(F.getPrologueData()) : J(nullptr)}};
    A Args;
    for (auto &Arg : F.args())
      Args.push_back(O{{"id", E.P->Values.at(&Arg)}, {"name", Arg.getName().str()},
                       {"type", E.type(Arg.getType())}});
    R["arguments"] = std::move(Args);
    A Blocks;
    for (auto &B : F) {
      noDebugRecords(B);
      A Insts;
      for (auto &I : B) {
        O Inst = encodeInstruction(I, E);
        Inst["id"] = E.P->Values.at(&I);
        Inst["name"] = I.getName().str();
        Inst["metadata"] = attachments(I, E);
        Insts.push_back(std::move(Inst));
      }
      Blocks.push_back(O{{"id", E.P->Values.at(&B)}, {"name", B.getName().str()},
                         {"instructions", std::move(Insts)}});
    }
    R["blocks"] = std::move(Blocks);
    Functions.push_back(std::move(R));
  }
  Root["globals"] = std::move(Globals);
  Root["aliases"] = std::move(Aliases);
  Root["ifuncs"] = std::move(IFuncs);
  Root["functions"] = std::move(Functions);
  A Named;
  for (auto &N : M.named_metadata()) {
    A Ops;
    for (auto *Op : N.operands()) Ops.push_back(E.metadata(Op));
    Named.push_back(O{{"name", N.getName().str()}, {"operands", std::move(Ops)}});
  }
  Root["named_metadata"] = std::move(Named);
  Root["types"] = std::move(E.P->TypeDefs);
  Root["metadata"] = std::move(E.P->MDDefs);
  return Root;
}

std::unique_ptr<Module> decodeModule(const J &Document, LLVMContext &C) {
  auto &Root = obj(Document);
  keys(Root, {"schema", "llvm_major", "profile", "module", "metadata_kind_names",
              "comdats", "globals", "aliases", "ifuncs", "functions",
              "named_metadata", "types", "metadata"});
  if (str(Root, "schema") != "hepta.hia.system.v1" ||
      uint(Root, "llvm_major") != 20 ||
      str(Root, "profile") != "unsafe-systems-explicit-memory")
    fail("unsupported systems dialect, version, or profile");
  auto &MO = obj(req(Root, "module"));
  keys(MO, {"identifier", "source_filename", "target_triple", "data_layout",
            "inline_asm_hex", "new_debug_format"});
  auto M = std::make_unique<Module>(str(MO, "identifier"), C);
  M->setSourceFileName(str(MO, "source_filename"));
  M->setTargetTriple(str(MO, "target_triple"));
  auto DL = DataLayout::parse(str(MO, "data_layout"));
  if (!DL) fail(Twine("invalid data layout: ") + toString(DL.takeError()));
  M->setDataLayout(*DL);
  M->setModuleInlineAsm(unhex(req(MO, "inline_asm_hex")));
  M->setNewDbgInfoFormatFlag(boolean(MO, "new_debug_format"));
  Decoder D(C, *M);
  unsigned ExpectedKind = 0;
  for (auto &Name : arr(req(Root, "metadata_kind_names"))) {
    unsigned Actual = C.getMDKindID(str(Name));
    if (Actual != ExpectedKind++) fail("metadata kind table order mismatch");
  }
  for (auto &Entry : arr(req(Root, "types"))) {
    auto &O = obj(Entry);
    auto ID = str(O, "id");
    if (!D.P->TypeDefs.emplace(ID, &O).second) fail("duplicate type ID");
    if (str(O, "kind") == "struct" && !boolean(O, "literal")) {
      keys(O, {"id", "kind", "literal", "name", "opaque", "packed", "elements"});
      auto Name = str(O, "name");
      if (!Name.empty() && StructType::getTypeByName(C, Name))
        fail("duplicate identified type name");
      D.P->Types[ID] = StructType::create(C, Name);
    }
  }
  for (auto &Entry : arr(req(Root, "types"))) {
    auto &O = obj(Entry);
    auto ID = str(O, "id");
    if (str(O, "kind") == "struct" && !boolean(O, "literal")) {
      auto *ST = needTy<StructType>(D.P->Types.at(ID), "struct");
      auto &Elems = arr(req(O, "elements"));
      if (boolean(O, "opaque")) {
        if (!Elems.empty() || boolean(O, "packed")) fail("opaque structure has body");
      } else {
        std::vector<Type *> Types;
        for (auto &E : Elems) {
          auto *T = D.type(E);
          if (!StructType::isValidElementType(T)) fail("invalid structure element");
          Types.push_back(T);
        }
        ST->setBody(Types, boolean(O, "packed"));
      }
    } else D.type(J(ID));
  }
  for (auto &Entry : arr(req(Root, "metadata"))) {
    auto &O = obj(Entry);
    if (!D.P->MDDefs.emplace(str(O, "id"), &O).second)
      fail("duplicate metadata ID");
  }
  for (auto &Entry : arr(req(Root, "comdats"))) {
    auto &O = obj(Entry);
    keys(O, {"name", "selection"});
    auto Name = str(O, "name");
    if (Name.empty() || M->getComdatSymbolTable().count(Name))
      fail("empty or duplicate comdat");
    auto *CD = M->getOrInsertComdat(Name);
    CD->setSelectionKind(Comdat::SelectionKind(uint(O, "selection", 4)));
  }

  // Allocate every global and every basic block before decoding initializers.
  // This makes blockaddress, cross-function and cyclic global references real
  // symbols, without smuggling an old LLVM module into the reconstruction.
  for (auto &Entry : arr(req(Root, "globals"))) {
    auto &O = obj(Entry);
    keys(O, {"id", "name", "value_type", "address_space", "properties", "object",
              "constant", "externally_initialized", "initializer", "attributes", "code_model"});
    auto *T = D.type(req(O, "value_type"));
    auto *G = new GlobalVariable(*M, T, boolean(O, "constant"), linkage(O),
        nullptr, str(O, "name"), nullptr, GlobalValue::NotThreadLocal,
        addressSpace(O), boolean(O, "externally_initialized"));
    D.bind(str(O, "id"), G);
    setCommon(*G, req(O, "properties"));
    setGlobalObject(*G, req(O, "object"), D);
    auto Attrs = D.attributes(req(O, "attributes"));
    for (unsigned Index : Attrs.indexes())
      if (Index != AttributeList::FunctionIndex &&
          Attrs.getAttributes(Index).hasAttributes())
        fail("non-function slot in global attribute set");
    G->setAttributes(Attrs.getFnAttrs());
    if (req(O, "code_model").kind() != J::Null)
      G->setCodeModel(CodeModel::Model(uint(req(O, "code_model"), CodeModel::Large)));
  }
  for (auto &Entry : arr(req(Root, "aliases"))) {
    auto &O = obj(Entry);
    keys(O, {"id", "name", "value_type", "address_space", "properties", "aliasee"});
    auto *G = GlobalAlias::create(D.type(req(O, "value_type")), addressSpace(O),
                                   linkage(O), str(O, "name"), M.get());
    D.bind(str(O, "id"), G);
    setCommon(*G, req(O, "properties"));
  }
  for (auto &Entry : arr(req(Root, "ifuncs"))) {
    auto &O = obj(Entry);
    keys(O, {"id", "name", "value_type", "address_space", "properties", "object", "resolver"});
    auto *G = GlobalIFunc::create(D.type(req(O, "value_type")), addressSpace(O),
                                  linkage(O), str(O, "name"), nullptr, M.get());
    D.bind(str(O, "id"), G);
    setCommon(*G, req(O, "properties"));
    setGlobalObject(*G, req(O, "object"), D);
  }
  std::set<std::string> SymbolNames;
  auto UniqueName = [&](GlobalValue &G, const O &O) {
    auto Name = str(O, "name");
    if (G.getName() != Name) fail("duplicate or altered global symbol name");
    if (!Name.empty() && !SymbolNames.insert(Name).second) fail("duplicate symbol");
  };
  for (auto &Entry : arr(req(Root, "globals"))) {
    auto &O = obj(Entry); UniqueName(*cast<GlobalValue>(D.P->Values.at(str(O, "id"))), O);
  }
  for (auto &Entry : arr(req(Root, "aliases"))) {
    auto &O = obj(Entry); UniqueName(*cast<GlobalValue>(D.P->Values.at(str(O, "id"))), O);
  }
  for (auto &Entry : arr(req(Root, "ifuncs"))) {
    auto &O = obj(Entry); UniqueName(*cast<GlobalValue>(D.P->Values.at(str(O, "id"))), O);
  }
  for (auto &Entry : arr(req(Root, "functions"))) {
    auto &O = obj(Entry);
    keys(O, {"id", "name", "value_type", "address_space", "properties", "object",
              "calling_convention", "attributes", "gc", "personality", "prefix",
              "prologue", "arguments", "blocks"});
    auto *FT = needTy<FunctionType>(D.type(req(O, "value_type")), "function");
    auto *F = Function::Create(FT, linkage(O), addressSpace(O), str(O, "name"), M.get());
    D.bind(str(O, "id"), F);
    UniqueName(*F, O);
    setCommon(*F, req(O, "properties"));
    setGlobalObject(*F, req(O, "object"), D);
    F->setCallingConv(uint(O, "calling_convention", CallingConv::MaxID));
    F->setAttributes(D.attributes(req(O, "attributes")));
    if (req(O, "gc").kind() != J::Null) F->setGC(str(req(O, "gc")));
    auto &Args = arr(req(O, "arguments"));
    if (Args.size() != F->arg_size()) fail("function parameter count mismatch");
    unsigned N = 0;
    for (auto &Arg : F->args()) {
      auto &AO = obj(Args[N++]);
      keys(AO, {"id", "name", "type"});
      if (D.type(req(AO, "type")) != Arg.getType()) fail("function parameter type mismatch");
      Arg.setName(str(AO, "name"));
      if (Arg.getName() != str(AO, "name")) fail("duplicate argument name");
      D.bind(str(AO, "id"), &Arg);
    }
    for (auto &Block : arr(req(O, "blocks"))) {
      auto &BO = obj(Block);
      keys(BO, {"id", "name", "instructions"});
      auto *B = BasicBlock::Create(C, str(BO, "name"), F);
      if (B->getName() != str(BO, "name")) fail("duplicate block name");
      D.bind(str(BO, "id"), B);
    }
  }
  for (auto &Entry : arr(req(Root, "globals"))) {
    auto &O = obj(Entry);
    auto *G = cast<GlobalVariable>(D.P->Values.at(str(O, "id")));
    if (req(O, "initializer").kind() != J::Null) {
      auto *Init = constant(D, req(O, "initializer"));
      if (Init->getType() != G->getValueType()) fail("global initializer type mismatch");
      G->setInitializer(Init);
    }
  }
  for (auto &Entry : arr(req(Root, "aliases"))) {
    auto &O = obj(Entry);
    cast<GlobalAlias>(D.P->Values.at(str(O, "id")))->setAliasee(constant(D, req(O, "aliasee")));
  }
  for (auto &Entry : arr(req(Root, "ifuncs"))) {
    auto &O = obj(Entry);
    cast<GlobalIFunc>(D.P->Values.at(str(O, "id")))->setResolver(constant(D, req(O, "resolver")));
  }
  for (auto &Entry : arr(req(Root, "functions"))) {
    auto &O = obj(Entry);
    auto *F = cast<Function>(D.P->Values.at(str(O, "id")));
    if (req(O, "personality").kind() != J::Null) F->setPersonalityFn(constant(D, req(O, "personality")));
    if (req(O, "prefix").kind() != J::Null) F->setPrefixData(constant(D, req(O, "prefix")));
    if (req(O, "prologue").kind() != J::Null) F->setPrologueData(constant(D, req(O, "prologue")));
    for (auto &Block : arr(req(O, "blocks"))) {
      auto &BO = obj(Block);
      auto *B = cast<BasicBlock>(D.P->Values.at(str(BO, "id")));
      for (auto &Inst : arr(req(BO, "instructions"))) {
        auto &IO = obj(Inst);
        auto *I = decodeInstruction(IO, D, B);
        if (!I || I->getParent() != B) fail("instruction decoder did not append to block");
        I->setName(str(IO, "name"));
        if (I->getName() != str(IO, "name")) fail("duplicate or invalid instruction name");
        D.bind(str(IO, "id"), I);
      }
    }
  }
  // Attach metadata only after the entire SSA graph has been reconstructed.
  for (auto Key : {"globals", "ifuncs", "functions"}) {
    for (auto &Entry : arr(req(Root, Key))) {
      auto &O = obj(Entry);
      auto *G = cast<GlobalObject>(D.P->Values.at(str(O, "id")));
      setAttachments(*G, req(obj(req(O, "object")), "metadata"), D);
    }
  }
  for (auto &Entry : arr(req(Root, "functions"))) {
    auto &O = obj(Entry);
    for (auto &Block : arr(req(O, "blocks"))) {
      for (auto &Inst : arr(req(obj(Block), "instructions"))) {
        auto &IO = obj(Inst);
        auto *I = cast<Instruction>(D.P->Values.at(str(IO, "id")));
        setAttachments(*I, req(IO, "metadata"), D);
      }
    }
  }
  std::set<std::string> NamedSeen;
  for (auto &Entry : arr(req(Root, "named_metadata"))) {
    auto &O = obj(Entry);
    keys(O, {"name", "operands"});
    auto Name = str(O, "name");
    if (Name.empty() || !NamedSeen.insert(Name).second) fail("invalid named metadata name");
    auto *N = M->getOrInsertNamedMetadata(Name);
    for (auto &Operand : arr(req(O, "operands"))) {
      auto *Node = dyn_cast_or_null<MDNode>(D.metadata(Operand));
      if (!Node) fail("named metadata operand is not a node");
      N->addOperand(Node);
    }
  }
  D.finish();
  return M;
}

O inspectModule(const Module &M) {
  uint64_t Definitions = 0, Blocks = 0, Insts = 0, InlineAsmCalls = 0;
  uint64_t Loads = 0, Stores = 0, Atomics = 0;
  std::map<std::string, uint64_t> Counts;
  for (auto &F : M) {
    if (!F.isDeclaration()) ++Definitions;
    for (auto &B : F) {
      ++Blocks;
      for (auto &I : B) {
        ++Insts; ++Counts[I.getOpcodeName()];
        if (isa<LoadInst>(I)) ++Loads;
        if (isa<StoreInst>(I)) ++Stores;
        if (I.isAtomic()) ++Atomics;
        if (auto *CB = dyn_cast<CallBase>(&I))
          if (CB->isInlineAsm()) ++InlineAsmCalls;
      }
    }
  }
  O Ops;
  for (auto &E : Counts) Ops[E.first] = int64_t(E.second);
  return O{{"schema", "hepta.hia.system.receipt.v1"},
      {"dialect", "hepta.hia.system.v1"}, {"llvm_major", int64_t(20)},
      {"verified_fresh_reconstruction", true},
      {"original_llvm_body_reused", false},
      {"legacy_hia_safe_core_proof", false},
      {"profile", "unsafe-systems-explicit-memory"},
      {"target_triple", M.getTargetTriple()}, {"data_layout", M.getDataLayoutStr()},
      {"globals", int64_t(M.global_size())}, {"aliases", int64_t(M.alias_size())},
      {"ifuncs", int64_t(M.ifunc_size())}, {"functions", int64_t(M.size())},
      {"defined_functions", int64_t(Definitions)}, {"blocks", int64_t(Blocks)},
      {"instructions", int64_t(Insts)}, {"loads", int64_t(Loads)},
      {"stores", int64_t(Stores)}, {"atomic_instructions", int64_t(Atomics)},
      {"inline_asm_calls", int64_t(InlineAsmCalls)},
      {"module_asm_bytes", int64_t(M.getModuleInlineAsm().size())},
      {"opcodes", std::move(Ops)}};
}
} // namespace hia

namespace {
void writeJSON(llvm::StringRef Path, const hia::J &Value) {
  std::error_code EC;
  llvm::raw_fd_ostream Out(Path, EC, llvm::sys::fs::OF_None);
  if (EC) hia::fail(llvm::Twine("cannot open output: ") + EC.message());
  Out << llvm::formatv("{0}", Value) << '\n';
  Out.flush();
  if (Out.has_error()) hia::fail("JSON output failed");
}
hia::J readJSON(llvm::StringRef Path) {
  auto Buffer = llvm::MemoryBuffer::getFile(Path);
  if (!Buffer) hia::fail(llvm::Twine("cannot read input: ") + Buffer.getError().message());
  auto Parsed = llvm::json::parse((*Buffer)->getBuffer());
  if (!Parsed) hia::fail(llvm::Twine("invalid JSON: ") + llvm::toString(Parsed.takeError()));
  return std::move(*Parsed);
}
} // namespace

int main(int Argc, char **Argv) {
  if (Argc != 4) {
    llvm::errs() << "usage: hia-system encode INPUT.bc OUTPUT.hia.json\n"
                   "       hia-system decode INPUT.hia.json OUTPUT.bc\n"
                   "       hia-system inspect INPUT.hia.json OUTPUT.receipt.json\n";
    return 2;
  }
  llvm::StringRef Mode(Argv[1]);
  llvm::LLVMContext Context;
  Context.setDiscardValueNames(false);
  if (Mode == "encode") {
    llvm::SMDiagnostic Error;
    auto Module = llvm::parseIRFile(Argv[2], Error, Context);
    if (!Module) { Error.print("hia-system", llvm::errs()); return 1; }
    writeJSON(Argv[3], hia::encodeModule(*Module));
  } else if (Mode == "decode" || Mode == "inspect") {
    auto Document = readJSON(Argv[2]);
    auto Module = hia::decodeModule(Document, Context);
    if (Mode == "inspect") {
      writeJSON(Argv[3], hia::inspectModule(*Module));
    } else {
      std::error_code EC;
      llvm::raw_fd_ostream Out(Argv[3], EC, llvm::sys::fs::OF_None);
      if (EC) hia::fail(llvm::Twine("cannot open bitcode output: ") + EC.message());
      llvm::WriteBitcodeToFile(*Module, Out, false);
      Out.flush();
      if (Out.has_error()) hia::fail("bitcode output failed");
    }
  } else hia::fail("unknown command");
  return 0;
}
