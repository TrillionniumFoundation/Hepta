// Copyright (c) Hepta contributors. SPDX-License-Identifier: MIT
// Explicit LLVM 20 debug metadata fields; never printed LLVM metadata text.
#include "system_wire.h"
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Casting.h"

static_assert(LLVM_VERSION_MAJOR == 20 && LLVM_VERSION_MINOR == 1 &&
              LLVM_VERSION_PATCH == 8, "HIA debug metadata requires LLVM 20.1.8");
namespace hia {
using namespace llvm;
namespace {
const J &req(const O &V, StringRef Key) {
  auto *R=V.get(Key); if(!R) fail(Twine("missing debug metadata field: ")+Key); return *R;
}
const O &object(const J &V) {
  auto *R=V.getAsObject(); if(!R) fail("debug metadata object required"); return *R;
}
const A &array(const J &V) {
  auto *R=V.getAsArray(); if(!R) fail("debug metadata array required"); return *R;
}
StringRef string(const J &V) {
  auto R=V.getAsString(); if(!R) fail("debug metadata string required"); return *R;
}
uint64_t u(const O &V, StringRef Key, uint64_t Max) {
  auto R=req(V,Key).getAsInteger();
  if(!R || *R<0 || uint64_t(*R)>Max) fail(Twine("debug unsigned field out of range: ")+Key);
  return uint64_t(*R);
}
int32_t signed32(const O &V, StringRef Key) {
  auto R=req(V,Key).getAsInteger();
  if(!R || *R<INT32_MIN || *R>INT32_MAX) fail("debug signed field out of range");
  return int32_t(*R);
}
bool boolean(const O &V, StringRef Key) {
  auto R=req(V,Key).getAsBoolean(); if(!R) fail("debug boolean required"); return *R;
}
uint64_t decimal(const O &V, StringRef Key) {
  auto S=string(req(V,Key)); uint64_t R;
  if(S.empty() || S.getAsInteger(10,R)) fail("invalid debug unsigned decimal");
  return R;
}
void keys(const O &V, std::initializer_list<StringRef> Allowed) {
  for(auto &KV:V) {
    bool Seen=false; for(auto K:Allowed) if(StringRef(KV.first)==K) Seen=true;
    if(!Seen) fail(Twine("unknown debug metadata field: ")+StringRef(KV.first));
  }
}
Metadata *md(const O &V, StringRef Key, Decoder &D) { return D.metadata(req(V,Key)); }
MDString *ms(const O &V, StringRef Key, Decoder &D) {
  auto *M=md(V,Key,D);
  if(M && !isa<MDString>(M)) fail(Twine("debug string node required: ")+Key);
  return cast_or_null<MDString>(M);
}
std::optional<unsigned> optionalUnsigned(const O &V, StringRef Key, uint64_t Max) {
  if(req(V,Key).kind()==J::Null) return std::nullopt;
  return unsigned(u(V,Key,Max));
}
std::optional<DIDerivedType::PtrAuthData> pointerAuth(const O &V) {
  auto Raw=optionalUnsigned(V,"pointer_auth_raw",0x7fffff);
  if(!Raw) return std::nullopt;
  return DIDerivedType::PtrAuthData(*Raw);
}
std::string apbits(const APInt &V) {
  SmallString<80> S; V.toString(S,16,false); return S.str().str();
}
} // namespace

O encodeDebugMetadata(const Metadata &Value, Encoder &E) {
  if(auto *N=dyn_cast<DIArgList>(&Value)) {
    A Args; for(auto *V:N->getArgs()) Args.push_back(E.metadata(V));
    return O{{"kind","DIArgList"},{"arguments",std::move(Args)}};
  }
  auto *Node=dyn_cast<MDNode>(&Value);
  if(!Node || Node->isTemporary()) fail("unsupported or temporary debug metadata");
  if(auto *N=dyn_cast<DIBasicType>(&Value)) {
    return O{{"kind","DIBasicType"},{"distinct",N->isDistinct()},
      {"tag",int64_t(N->getTag())},
      {"name",E.metadata(N->getRawName())},
      {"size_bits",std::to_string(N->getSizeInBits())},
      {"align_bits",int64_t(N->getAlignInBits())},
      {"encoding",int64_t(N->getEncoding())},
      {"extra_inhabitants",int64_t(N->getNumExtraInhabitants())},
      {"flags",int64_t(N->getFlags())}};
  }
  if(auto *N=dyn_cast<DIDerivedType>(&Value)) {
    return O{{"kind","DIDerivedType"},{"distinct",N->isDistinct()},
      {"tag",int64_t(N->getTag())},
      {"name",E.metadata(N->getRawName())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())},
      {"scope",E.metadata(N->getRawScope())},
      {"base_type",E.metadata(N->getRawBaseType())},
      {"size_bits",std::to_string(N->getSizeInBits())},
      {"align_bits",int64_t(N->getAlignInBits())},
      {"offset_bits",std::to_string(N->getOffsetInBits())},
      {"dwarf_address_space",N->getDWARFAddressSpace() ? J(int64_t(*N->getDWARFAddressSpace())) : J(nullptr)},
      {"pointer_auth_raw",N->getPtrAuthData() ? J(int64_t(N->getPtrAuthData()->RawData)) : J(nullptr)},
      {"flags",int64_t(N->getFlags())},
      {"extra_data",E.metadata(N->getRawExtraData())},
      {"annotations",E.metadata(N->getRawAnnotations())}};
  }
  if(auto *N=dyn_cast<DICompositeType>(&Value)) {
    return O{{"kind","DICompositeType"},{"distinct",N->isDistinct()},
      {"tag",int64_t(N->getTag())},
      {"name",E.metadata(N->getRawName())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())},
      {"scope",E.metadata(N->getRawScope())},
      {"base_type",E.metadata(N->getRawBaseType())},
      {"size_bits",std::to_string(N->getSizeInBits())},
      {"align_bits",int64_t(N->getAlignInBits())},
      {"offset_bits",std::to_string(N->getOffsetInBits())},
      {"flags",int64_t(N->getFlags())},
      {"elements",E.metadata(N->getRawElements())},
      {"runtime_language",int64_t(N->getRuntimeLang())},
      {"vtable_holder",E.metadata(N->getRawVTableHolder())},
      {"template_parameters",E.metadata(N->getRawTemplateParams())},
      {"identifier",E.metadata(N->getRawIdentifier())},
      {"discriminator",E.metadata(N->getRawDiscriminator())},
      {"data_location",E.metadata(N->getRawDataLocation())},
      {"associated",E.metadata(N->getRawAssociated())},
      {"allocated",E.metadata(N->getRawAllocated())},
      {"rank",E.metadata(N->getRawRank())},
      {"annotations",E.metadata(N->getRawAnnotations())},
      {"specification",E.metadata(N->getRawSpecification())},
      {"extra_inhabitants",int64_t(N->getNumExtraInhabitants())}};
  }
  if(auto *N=dyn_cast<DISubroutineType>(&Value)) {
    return O{{"kind","DISubroutineType"},{"distinct",N->isDistinct()},
      {"flags",int64_t(N->getFlags())},
      {"calling_convention",int64_t(N->getCC())},
      {"types",E.metadata(N->getRawTypeArray())}};
  }
  if(auto *N=dyn_cast<DICompileUnit>(&Value)) {
    return O{{"kind","DICompileUnit"},{"distinct",N->isDistinct()},
      {"source_language",int64_t(N->getSourceLanguage())},
      {"file",E.metadata(N->getRawFile())},
      {"producer",E.metadata(N->getRawProducer())},
      {"optimized",N->isOptimized()},
      {"flags_string",E.metadata(N->getRawFlags())},
      {"runtime_version",int64_t(N->getRuntimeVersion())},
      {"split_debug_filename",E.metadata(N->getRawSplitDebugFilename())},
      {"emission_kind",int64_t(N->getEmissionKind())},
      {"enum_types",E.metadata(N->getRawEnumTypes())},
      {"retained_types",E.metadata(N->getRawRetainedTypes())},
      {"global_variables",E.metadata(N->getRawGlobalVariables())},
      {"imported_entities",E.metadata(N->getRawImportedEntities())},
      {"macros",E.metadata(N->getRawMacros())},
      {"dwo_id",std::to_string(N->getDWOId())},
      {"split_debug_inlining",N->getSplitDebugInlining()},
      {"debug_info_for_profiling",N->getDebugInfoForProfiling()},
      {"name_table_kind",int64_t(N->getNameTableKind())},
      {"ranges_base_address",N->getRangesBaseAddress()},
      {"sysroot",E.metadata(N->getRawSysRoot())},
      {"sdk",E.metadata(N->getRawSDK())}};
  }
  if(auto *N=dyn_cast<DISubprogram>(&Value)) {
    return O{{"kind","DISubprogram"},{"distinct",N->isDistinct()},
      {"scope",E.metadata(N->getRawScope())},
      {"name",E.metadata(N->getRawName())},
      {"linkage_name",E.metadata(N->getRawLinkageName())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())},
      {"type",E.metadata(N->getRawType())},
      {"scope_line",int64_t(N->getScopeLine())},
      {"containing_type",E.metadata(N->getRawContainingType())},
      {"virtual_index",int64_t(N->getVirtualIndex())},
      {"this_adjustment",int64_t(N->getThisAdjustment())},
      {"flags",int64_t(N->getFlags())},
      {"subprogram_flags",int64_t(N->getSPFlags())},
      {"unit",E.metadata(N->getRawUnit())},
      {"template_parameters",E.metadata(N->getRawTemplateParams())},
      {"declaration",E.metadata(N->getRawDeclaration())},
      {"retained_nodes",E.metadata(N->getRawRetainedNodes())},
      {"thrown_types",E.metadata(N->getRawThrownTypes())},
      {"annotations",E.metadata(N->getRawAnnotations())},
      {"target_function_name",E.metadata(N->getRawTargetFuncName())}};
  }
  if(auto *N=dyn_cast<DILocation>(&Value)) {
    return O{{"kind","DILocation"},{"distinct",N->isDistinct()},
      {"line",int64_t(N->getLine())},
      {"column",int64_t(N->getColumn())},
      {"scope",E.metadata(N->getRawScope())},
      {"inlined_at",E.metadata(N->getRawInlinedAt())},
      {"implicit_code",N->isImplicitCode()}};
  }
  if(auto *N=dyn_cast<DILocalVariable>(&Value)) {
    return O{{"kind","DILocalVariable"},{"distinct",N->isDistinct()},
      {"scope",E.metadata(N->getRawScope())},
      {"name",E.metadata(N->getRawName())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())},
      {"type",E.metadata(N->getRawType())},
      {"argument",int64_t(N->getArg())},
      {"flags",int64_t(N->getFlags())},
      {"align_bits",int64_t(N->getAlignInBits())},
      {"annotations",E.metadata(N->getRawAnnotations())}};
  }
  if(auto *N=dyn_cast<DILexicalBlock>(&Value)) {
    return O{{"kind","DILexicalBlock"},{"distinct",N->isDistinct()},
      {"scope",E.metadata(N->getRawScope())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())},
      {"column",int64_t(N->getColumn())}};
  }
  if(auto *N=dyn_cast<DILexicalBlockFile>(&Value)) {
    return O{{"kind","DILexicalBlockFile"},{"distinct",N->isDistinct()},
      {"scope",E.metadata(N->getRawScope())},
      {"file",E.metadata(N->getRawFile())},
      {"discriminator",int64_t(N->getDiscriminator())}};
  }
  if(auto *N=dyn_cast<DIGlobalVariable>(&Value)) {
    if(N->getDisplayName()!=N->getName()) fail("unrepresented legacy debug display name");
    return O{{"kind","DIGlobalVariable"},{"distinct",N->isDistinct()},
      {"scope",E.metadata(N->getRawScope())},
      {"name",E.metadata(N->getRawName())},
      {"linkage_name",E.metadata(N->getRawLinkageName())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())},
      {"type",E.metadata(N->getRawType())},
      {"local_to_unit",N->isLocalToUnit()},
      {"definition",N->isDefinition()},
      {"static_data_member_declaration",E.metadata(N->getRawStaticDataMemberDeclaration())},
      {"template_parameters",E.metadata(N->getRawTemplateParams())},
      {"align_bits",int64_t(N->getAlignInBits())},
      {"annotations",E.metadata(N->getRawAnnotations())}};
  }
  if(auto *N=dyn_cast<DIGlobalVariableExpression>(&Value)) {
    return O{{"kind","DIGlobalVariableExpression"},{"distinct",N->isDistinct()},
      {"variable",E.metadata(N->getRawVariable())},
      {"expression",E.metadata(N->getRawExpression())}};
  }
  if(auto *N=dyn_cast<DISubrange>(&Value)) {
    return O{{"kind","DISubrange"},{"distinct",N->isDistinct()},
      {"count",E.metadata(N->getRawCountNode())},
      {"lower_bound",E.metadata(N->getRawLowerBound())},
      {"upper_bound",E.metadata(N->getRawUpperBound())},
      {"stride",E.metadata(N->getRawStride())}};
  }
  if(auto *N=dyn_cast<DILabel>(&Value)) {
    return O{{"kind","DILabel"},{"distinct",N->isDistinct()},
      {"scope",E.metadata(N->getRawScope())},
      {"name",E.metadata(N->getRawName())},
      {"file",E.metadata(N->getRawFile())},
      {"line",int64_t(N->getLine())}};
  }
  if(auto *N=dyn_cast<DIFile>(&Value)) {
    J Checksum=nullptr;
    if(auto CS=N->getRawChecksum())
      Checksum=O{{"kind",int64_t(CS->Kind)},{"value",E.metadata(CS->Value)}};
    return O{{"kind","DIFile"},{"distinct",N->isDistinct()},
      {"filename",E.metadata(N->getRawFilename())},{"directory",E.metadata(N->getRawDirectory())},
      {"checksum",std::move(Checksum)},{"source",E.metadata(N->getRawSource())}};
  }
  if(auto *N=dyn_cast<DIExpression>(&Value)) {
    A Values; for(auto V:N->getElements()) Values.push_back(std::to_string(V));
    return O{{"kind","DIExpression"},{"distinct",N->isDistinct()},{"elements",std::move(Values)}};
  }
  if(auto *N=dyn_cast<DIEnumerator>(&Value))
    return O{{"kind","DIEnumerator"},{"distinct",N->isDistinct()},
      {"width",int64_t(N->getValue().getBitWidth())},{"value_hex",apbits(N->getValue())},
      {"unsigned",N->isUnsigned()},{"name",E.metadata(N->getRawName())}};
  if(auto *N=dyn_cast<DIAssignID>(&Value))
    return O{{"kind","DIAssignID"},{"distinct",N->isDistinct()}};
  fail(Twine("unsupported structured debug metadata kind: ")+Twine(Value.getMetadataID()));
}

Metadata *decodeDebugMetadata(const O &O, Decoder &D) {
  auto &C=D.context();
  auto K=string(req(O,"kind"));
  if(K=="DIArgList") {
    keys(O,{"id","kind","arguments"});
    std::vector<ValueAsMetadata *> Args;
    for(auto &Entry:array(req(O,"arguments"))) {
      auto *V=D.metadata(Entry);
      if(!isa_and_nonnull<ValueAsMetadata>(V)) fail("DIArgList requires value metadata");
      Args.push_back(cast<ValueAsMetadata>(V));
    }
    return DIArgList::get(C,Args);
  }
  bool Distinct=boolean(O,"distinct");
#define NODE(CLASS, ...) (Distinct ? CLASS::getDistinct(C, __VA_ARGS__) : CLASS::get(C, __VA_ARGS__))
  if(K=="DIBasicType") {
    keys(O,{"id","kind","distinct","tag","name","size_bits","align_bits","encoding","extra_inhabitants","flags"});
    return NODE(DIBasicType,
      u(O,"tag",UINT16_MAX),
      ms(O,"name",D),
      decimal(O,"size_bits"),
      u(O,"align_bits",UINT32_MAX),
      u(O,"encoding",UINT32_MAX),
      u(O,"extra_inhabitants",UINT32_MAX),
      DINode::DIFlags(u(O,"flags",UINT32_MAX)));
  }
  if(K=="DIDerivedType") {
    keys(O,{"id","kind","distinct","tag","name","file","line","scope","base_type","size_bits","align_bits","offset_bits","dwarf_address_space","pointer_auth_raw","flags","extra_data","annotations"});
    return NODE(DIDerivedType,
      u(O,"tag",UINT16_MAX),
      ms(O,"name",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX),
      md(O,"scope",D),
      md(O,"base_type",D),
      decimal(O,"size_bits"),
      u(O,"align_bits",UINT32_MAX),
      decimal(O,"offset_bits"),
      optionalUnsigned(O,"dwarf_address_space",UINT32_MAX),
      pointerAuth(O),
      DINode::DIFlags(u(O,"flags",UINT32_MAX)),
      md(O,"extra_data",D),
      md(O,"annotations",D));
  }
  if(K=="DICompositeType") {
    keys(O,{"id","kind","distinct","tag","name","file","line","scope","base_type","size_bits","align_bits","offset_bits","flags","elements","runtime_language","vtable_holder","template_parameters","identifier","discriminator","data_location","associated","allocated","rank","annotations","specification","extra_inhabitants"});
    return NODE(DICompositeType,
      u(O,"tag",UINT16_MAX),
      ms(O,"name",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX),
      md(O,"scope",D),
      md(O,"base_type",D),
      decimal(O,"size_bits"),
      u(O,"align_bits",UINT32_MAX),
      decimal(O,"offset_bits"),
      DINode::DIFlags(u(O,"flags",UINT32_MAX)),
      md(O,"elements",D),
      u(O,"runtime_language",UINT32_MAX),
      md(O,"vtable_holder",D),
      md(O,"template_parameters",D),
      ms(O,"identifier",D),
      md(O,"discriminator",D),
      md(O,"data_location",D),
      md(O,"associated",D),
      md(O,"allocated",D),
      md(O,"rank",D),
      md(O,"annotations",D),
      md(O,"specification",D),
      u(O,"extra_inhabitants",UINT32_MAX));
  }
  if(K=="DISubroutineType") {
    keys(O,{"id","kind","distinct","flags","calling_convention","types"});
    return NODE(DISubroutineType,
      DINode::DIFlags(u(O,"flags",UINT32_MAX)),
      u(O,"calling_convention",UINT8_MAX),
      md(O,"types",D));
  }
  if(K=="DICompileUnit") {
    keys(O,{"id","kind","distinct","source_language","file","producer","optimized","flags_string","runtime_version","split_debug_filename","emission_kind","enum_types","retained_types","global_variables","imported_entities","macros","dwo_id","split_debug_inlining","debug_info_for_profiling","name_table_kind","ranges_base_address","sysroot","sdk"});
    if(!Distinct) fail("DICompileUnit must be distinct");
    return DICompileUnit::getDistinct(C,
      u(O,"source_language",UINT32_MAX),
      md(O,"file",D),
      ms(O,"producer",D),
      boolean(O,"optimized"),
      ms(O,"flags_string",D),
      u(O,"runtime_version",UINT32_MAX),
      ms(O,"split_debug_filename",D),
      u(O,"emission_kind",3),
      md(O,"enum_types",D),
      md(O,"retained_types",D),
      md(O,"global_variables",D),
      md(O,"imported_entities",D),
      md(O,"macros",D),
      decimal(O,"dwo_id"),
      boolean(O,"split_debug_inlining"),
      boolean(O,"debug_info_for_profiling"),
      u(O,"name_table_kind",3),
      boolean(O,"ranges_base_address"),
      ms(O,"sysroot",D),
      ms(O,"sdk",D));
  }
  if(K=="DISubprogram") {
    keys(O,{"id","kind","distinct","scope","name","linkage_name","file","line","type","scope_line","containing_type","virtual_index","this_adjustment","flags","subprogram_flags","unit","template_parameters","declaration","retained_nodes","thrown_types","annotations","target_function_name"});
    return NODE(DISubprogram,
      md(O,"scope",D),
      ms(O,"name",D),
      ms(O,"linkage_name",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX),
      md(O,"type",D),
      u(O,"scope_line",UINT32_MAX),
      md(O,"containing_type",D),
      u(O,"virtual_index",UINT32_MAX),
      signed32(O,"this_adjustment"),
      DINode::DIFlags(u(O,"flags",UINT32_MAX)),
      DISubprogram::DISPFlags(u(O,"subprogram_flags",UINT32_MAX)),
      md(O,"unit",D),
      md(O,"template_parameters",D),
      md(O,"declaration",D),
      md(O,"retained_nodes",D),
      md(O,"thrown_types",D),
      md(O,"annotations",D),
      ms(O,"target_function_name",D));
  }
  if(K=="DILocation") {
    keys(O,{"id","kind","distinct","line","column","scope","inlined_at","implicit_code"});
    return NODE(DILocation,
      u(O,"line",UINT32_MAX),
      u(O,"column",UINT16_MAX),
      md(O,"scope",D),
      md(O,"inlined_at",D),
      boolean(O,"implicit_code"));
  }
  if(K=="DILocalVariable") {
    keys(O,{"id","kind","distinct","scope","name","file","line","type","argument","flags","align_bits","annotations"});
    return NODE(DILocalVariable,
      md(O,"scope",D),
      ms(O,"name",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX),
      md(O,"type",D),
      u(O,"argument",UINT16_MAX),
      DINode::DIFlags(u(O,"flags",UINT32_MAX)),
      u(O,"align_bits",UINT32_MAX),
      md(O,"annotations",D));
  }
  if(K=="DILexicalBlock") {
    keys(O,{"id","kind","distinct","scope","file","line","column"});
    return NODE(DILexicalBlock,
      md(O,"scope",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX),
      u(O,"column",UINT16_MAX));
  }
  if(K=="DILexicalBlockFile") {
    keys(O,{"id","kind","distinct","scope","file","discriminator"});
    return NODE(DILexicalBlockFile,
      md(O,"scope",D),
      md(O,"file",D),
      u(O,"discriminator",UINT32_MAX));
  }
  if(K=="DIGlobalVariable") {
    keys(O,{"id","kind","distinct","scope","name","linkage_name","file","line","type","local_to_unit","definition","static_data_member_declaration","template_parameters","align_bits","annotations"});
    return NODE(DIGlobalVariable,
      md(O,"scope",D),
      ms(O,"name",D),
      ms(O,"linkage_name",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX),
      md(O,"type",D),
      boolean(O,"local_to_unit"),
      boolean(O,"definition"),
      md(O,"static_data_member_declaration",D),
      md(O,"template_parameters",D),
      u(O,"align_bits",UINT32_MAX),
      md(O,"annotations",D));
  }
  if(K=="DIGlobalVariableExpression") {
    keys(O,{"id","kind","distinct","variable","expression"});
    return NODE(DIGlobalVariableExpression,
      md(O,"variable",D),
      md(O,"expression",D));
  }
  if(K=="DISubrange") {
    keys(O,{"id","kind","distinct","count","lower_bound","upper_bound","stride"});
    return NODE(DISubrange,
      md(O,"count",D),
      md(O,"lower_bound",D),
      md(O,"upper_bound",D),
      md(O,"stride",D));
  }
  if(K=="DILabel") {
    keys(O,{"id","kind","distinct","scope","name","file","line"});
    return NODE(DILabel,
      md(O,"scope",D),
      ms(O,"name",D),
      md(O,"file",D),
      u(O,"line",UINT32_MAX));
  }
  if(K=="DIFile") {
    keys(O,{"id","kind","distinct","filename","directory","checksum","source"});
    std::optional<DIFile::ChecksumInfo<MDString *>> Checksum;
    if(req(O,"checksum").kind()!=J::Null) {
      auto &CS=object(req(O,"checksum"));
      keys(CS,{"kind","value"});
      unsigned Kind=u(CS,"kind",3);
      if(!Kind) fail("invalid DIFile checksum kind");
      auto *Value=ms(CS,"value",D);
      if(!Value) fail("missing DIFile checksum value");
      Checksum.emplace(DIFile::ChecksumKind(Kind),Value);
    }
    return NODE(DIFile,ms(O,"filename",D),ms(O,"directory",D),Checksum,ms(O,"source",D));
  }
  if(K=="DIExpression") {
    keys(O,{"id","kind","distinct","elements"});
    std::vector<uint64_t> Elements;
    for(auto &Entry:array(req(O,"elements"))) {
      auto S=string(Entry); uint64_t V;
      if(S.empty() || S.getAsInteger(10,V)) fail("invalid DIExpression element");
      Elements.push_back(V);
    }
    auto *N=NODE(DIExpression,Elements);
    if(!N->isValid()) fail("invalid or unsupported DIExpression operations");
    return N;
  }
  if(K=="DIEnumerator") {
    keys(O,{"id","kind","distinct","width","value_hex","unsigned","name"});
    unsigned Width=u(O,"width",1<<20);
    auto Hex=string(req(O,"value_hex"));
    if(!Width || Hex.empty()) fail("invalid DIEnumerator width or value");
    for(char C:Hex) if(!((C>='0'&&C<='9')||(C>='a'&&C<='f')||(C>='A'&&C<='F')))
      fail("invalid DIEnumerator hex digit");
    if(APInt::getBitsNeeded(Hex,16)>Width) fail("DIEnumerator value exceeds bit width");
    APInt V(Width,Hex,16);
    return NODE(DIEnumerator,V,boolean(O,"unsigned"),ms(O,"name",D));
  }
  if(K=="DIAssignID") {
    keys(O,{"id","kind","distinct"});
    if(!Distinct) fail("DIAssignID must be distinct");
    return DIAssignID::getDistinct(C);
  }
#undef NODE
  fail(Twine("unknown structured debug metadata kind: ")+K);
}
} // namespace hia
