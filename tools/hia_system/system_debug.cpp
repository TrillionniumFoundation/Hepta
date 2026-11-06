// SPDX-License-Identifier: MIT
// Position-preserving LLVM20 debug-record codec for HIA systems IR.
// Debug metadata is encoded by Encoder::metadata; no LLVM text is embedded.
#include "system_wire.h"

#include <set>
#include <string>
#include <utility>
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DebugProgramInstruction.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/Casting.h"

static_assert(LLVM_VERSION_MAJOR == 20 && LLVM_VERSION_MINOR == 1 &&
              LLVM_VERSION_PATCH == 8,
              "HIA debug-record codec is qualified for LLVM 20.1.8");

namespace hia {
namespace {
using namespace llvm;

class RecordFields {
  const O &Object;
  std::set<std::string> Read;
public:
  explicit RecordFields(const O &Object) : Object(Object) {}
  const J &get(StringRef Key) {
    Read.insert(Key.str());
    const J *Value = Object.get(Key);
    if (!Value)
      fail(Twine("missing debug record field: ") + Key);
    return *Value;
  }
  StringRef string(StringRef Key) {
    auto Value = get(Key).getAsString();
    if (!Value)
      fail(Twine("expected debug record string: ") + Key);
    return *Value;
  }
  void finish() const {
    for (const auto &Field : Object) {
      StringRef Key = Field.first;
      if (!Read.count(Key.str()))
        fail(Twine("unconsumed debug record field: ") + Key);
    }
  }
};

template <typename T>
T *typedMetadata(RecordFields &Fields, StringRef Key, Decoder &D,
                 bool Nullable = false) {
  Metadata *M = D.metadata(Fields.get(Key));
  if (!M && Nullable)
    return nullptr;
  T *Typed = dyn_cast_or_null<T>(M);
  if (!Typed)
    fail(Twine("invalid or unresolved debug metadata type: ") + Key);
  return Typed;
}

Metadata *variableLocation(RecordFields &Fields, StringRef Key, Decoder &D) {
  Metadata *M = D.metadata(Fields.get(Key));
  // Empty metadata is LLVM's explicit unavailable-location representation.
  // Reject arbitrary metadata in a value/address slot before constructing LLVM.
  const auto *Tuple = dyn_cast_or_null<MDTuple>(M);
  if (!M || !(isa<ValueAsMetadata>(M) || isa<DIArgList>(M) ||
              (Tuple && Tuple->getNumOperands() == 0)))
    fail(Twine("invalid debug variable location: ") + Key);
  return M;
}

O encodeRecord(const DbgRecord &Record, Encoder &E) {
  O Result;
  Result["debug_location"] = E.metadata(Record.getDebugLoc().getAsMDNode());
  if (const auto *Label = dyn_cast<DbgLabelRecord>(&Record)) {
    Result["kind"] = "dbg_label";
    Result["label"] = E.metadata(Label->getRawLabel());
    return Result;
  }
  const auto *Variable = dyn_cast<DbgVariableRecord>(&Record);
  if (!Variable)
    fail("unsupported debug record subclass");
  switch (Variable->getType()) {
  case DbgVariableRecord::LocationType::Declare:
    Result["kind"] = "dbg_declare";
    break;
  case DbgVariableRecord::LocationType::Value:
    Result["kind"] = "dbg_value";
    break;
  case DbgVariableRecord::LocationType::Assign:
    Result["kind"] = "dbg_assign";
    break;
  default:
    fail("unsupported debug variable record location type");
  }
  Result["location"] = E.metadata(Variable->getRawLocation());
  Result["variable"] = E.metadata(Variable->getRawVariable());
  Result["expression"] = E.metadata(Variable->getRawExpression());
  if (Variable->isDbgAssign()) {
    Result["assign_id"] = E.metadata(Variable->getRawAssignID());
    Result["address"] = E.metadata(Variable->getRawAddress());
    Result["address_expression"] =
        E.metadata(Variable->getRawAddressExpression());
  }
  return Result;
}

DbgRecord *decodeRecord(const J &Value, Decoder &D) {
  const O *Object = Value.getAsObject();
  if (!Object)
    fail("debug record must be a structured object");
  RecordFields Fields(*Object);
  StringRef Kind = Fields.string("kind");
  DILocation *Location =
      typedMetadata<DILocation>(Fields, "debug_location", D, true);
  if (Kind == "dbg_label") {
    DILabel *Label = typedMetadata<DILabel>(Fields, "label", D);
    Fields.finish();
    return new DbgLabelRecord(Label, DebugLoc(Location));
  }
  DbgVariableRecord::LocationType Type;
  if (Kind == "dbg_declare")
    Type = DbgVariableRecord::LocationType::Declare;
  else if (Kind == "dbg_value")
    Type = DbgVariableRecord::LocationType::Value;
  else if (Kind == "dbg_assign")
    Type = DbgVariableRecord::LocationType::Assign;
  else
    fail(Twine("unsupported debug record kind: ") + Kind);
  Metadata *ValueLocation = variableLocation(Fields, "location", D);
  DILocalVariable *Variable =
      typedMetadata<DILocalVariable>(Fields, "variable", D);
  DIExpression *Expression =
      typedMetadata<DIExpression>(Fields, "expression", D);
  if (Type == DbgVariableRecord::LocationType::Assign) {
    DIAssignID *AssignID = typedMetadata<DIAssignID>(Fields, "assign_id", D);
    Metadata *Address = variableLocation(Fields, "address", D);
    DIExpression *AddressExpression =
        typedMetadata<DIExpression>(Fields, "address_expression", D);
    Fields.finish();
    return new DbgVariableRecord(ValueLocation, Variable, Expression, AssignID,
                                 Address, AddressExpression, Location);
  }
  Fields.finish();
  return new DbgVariableRecord(ValueLocation, Variable, Expression, Location,
                               Type);
}

const A &recordArray(const J &Value) {
  const A *Records = Value.getAsArray();
  if (!Records)
    fail("debug record collection must be an ordered array");
  return *Records;
}

} // namespace

J encodeDebugRecords(const llvm::Instruction &I, Encoder &E) {
  A Records;
  for (const llvm::DbgRecord &Record : I.getDbgRecordRange())
    Records.push_back(encodeRecord(Record, E));
  return J(std::move(Records));
}

void decodeDebugRecords(const J &Value, Decoder &D, llvm::Instruction &I) {
  const A &Records = recordArray(Value);
  if (I.hasDbgRecords())
    fail("instruction already has debug records before HIA attachment");
  if (Records.empty())
    return;
  llvm::BasicBlock *Block = I.getParent();
  if (!Block || !Block->IsNewDbgInfoFormat)
    fail("debug records require a bound block in record debug-info format");
  llvm::DbgMarker *Marker = Block->createMarker(&I);
  // Append in source order: duplicate records and their positions matter.
  for (const J &Record : Records)
    Marker->insertDbgRecord(decodeRecord(Record, D), false);
}

J encodeTrailingDebugRecords(const llvm::BasicBlock &Block, Encoder &E) {
  A Records;
  // LLVM20 exposes this read-only lookup through a non-const member.
  const llvm::DbgMarker *Marker =
      const_cast<llvm::BasicBlock &>(Block).getTrailingDbgRecords();
  if (Marker)
    for (const llvm::DbgRecord &Record : Marker->getDbgRecordRange())
      Records.push_back(encodeRecord(Record, E));
  return J(std::move(Records));
}

void decodeTrailingDebugRecords(const J &Value, Decoder &D,
                                llvm::BasicBlock &Block) {
  const A &Records = recordArray(Value);
  const llvm::DbgMarker *Existing = Block.getTrailingDbgRecords();
  if (Existing && !Existing->empty())
    fail("block already has trailing debug records before HIA attachment");
  if (Records.empty())
    return;
  if (!Block.IsNewDbgInfoFormat)
    fail("trailing records require record debug-info format");
  // Preserve the exact off-end position. Do not flush into a terminator or
  // convert records to executable/intrinsic instructions.
  llvm::DbgMarker *Marker = Block.createMarker(Block.end());
  for (const J &Record : Records)
    Marker->insertDbgRecord(decodeRecord(Record, D), false);
}

} // namespace hia
