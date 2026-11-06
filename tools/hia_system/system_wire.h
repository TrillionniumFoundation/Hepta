#ifndef HEPTA_HIA_SYSTEM_WIRE_H
#define HEPTA_HIA_SYSTEM_WIRE_H

#include <memory>
#include <string>
#include "llvm/Support/JSON.h"

namespace llvm {
class Twine;
class Type;
class Value;
class Metadata;
class Instruction;
class BasicBlock;
class AttributeList;
class LLVMContext;
class Module;
}

namespace hia {
using J = llvm::json::Value;
using O = llvm::json::Object;
using A = llvm::json::Array;

[[noreturn]] void fail(const llvm::Twine &message);

// This is the explicit unsafe systems dialect, not VerifiedProgram v1-v8.
// JSON carries operations, typed values and properties, never LLVM body text.
class Encoder {
public:
  struct Impl;
  std::unique_ptr<Impl> P;
  explicit Encoder(const llvm::Module &module);
  ~Encoder();
  Encoder(const Encoder &) = delete;
  Encoder &operator=(const Encoder &) = delete;
  J type(const llvm::Type *value);
  J value(const llvm::Value *value);
  J attributes(const llvm::AttributeList &value);
  J metadata(const llvm::Metadata *value);
};

class Decoder {
public:
  struct Impl;
  std::unique_ptr<Impl> P;
  Decoder(llvm::LLVMContext &context, llvm::Module &module);
  ~Decoder();
  Decoder(const Decoder &) = delete;
  Decoder &operator=(const Decoder &) = delete;
  llvm::Type *type(const J &value);
  llvm::Value *value(const J &value);
  llvm::AttributeList attributes(const J &value);
  llvm::Metadata *metadata(const J &value);
  llvm::LLVMContext &context();
  llvm::Module &module();
  void bind(const std::string &id, llvm::Value *value);
  void finish();
};

O encodeDebugMetadata(const llvm::Metadata &metadata, Encoder &encoder);
llvm::Metadata *decodeDebugMetadata(const O &metadata, Decoder &decoder);
J encodeDebugRecords(const llvm::Instruction &instruction, Encoder &encoder);
void decodeDebugRecords(const J &records, Decoder &decoder, llvm::Instruction &instruction);
J encodeTrailingDebugRecords(const llvm::BasicBlock &block, Encoder &encoder);
void decodeTrailingDebugRecords(const J &records, Decoder &decoder, llvm::BasicBlock &block);

O encodeInstruction(const llvm::Instruction &instruction, Encoder &encoder);
llvm::Instruction *decodeInstruction(const O &instruction, Decoder &decoder,
                                    llvm::BasicBlock *block);
J encodeModule(const llvm::Module &module);
std::unique_ptr<llvm::Module> decodeModule(const J &document,
                                         llvm::LLVMContext &context);
O inspectModule(const llvm::Module &module);
} // namespace hia
#endif
