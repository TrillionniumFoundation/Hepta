#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/JSON.h"
#include "llvm-c/Core.h"
#include "llvm/Support/SHA256.h"
#include "llvm/ADT/StringExtras.h"
#include <memory>
using namespace clang;
struct Result { llvm::json::Array events; std::string ast, digest, target; unsigned pointer=0, lng=0, integer=0, longlong=0; size_t source_size=0; unsigned envelopes=0; bool bad=false; };
class Callbacks : public PPCallbacks {
 SourceManager &sm; Result &r;
 public: Callbacks(SourceManager &sm, Result &r):sm(sm),r(r){}
 void MacroExpands(const Token &tok, const MacroDefinition &, SourceRange, const MacroArgs *) override {
  auto loc=sm.getExpansionLoc(tok.getLocation());
  if(loc.isInvalid() || !loc.isFileID()) {r.bad=true;return;}
  if(sm.getFileID(loc)!=sm.getMainFileID()) return;
  if(r.events.size()>=4096 || !tok.getIdentifierInfo()) {r.bad=true;return;}
  r.events.push_back(llvm::json::Object{{"name",tok.getIdentifierInfo()->getName().str()},{"offset",sm.getFileOffset(loc)}});
 }
};
class Consumer : public ASTConsumer {
 CompilerInstance &ci; Result &r;
 public: Consumer(CompilerInstance &ci,Result &r):ci(ci),r(r){}
 void HandleTranslationUnit(ASTContext &ctx) override {
  ++r.envelopes;
  if(ci.getDiagnostics().hasErrorOccurred() || ci.getDiagnostics().hasFatalErrorOccurred()) {r.bad=true;return;}
  auto &sm=ci.getSourceManager();bool invalid=false;auto bytes=sm.getBufferData(sm.getMainFileID(),&invalid);
  if(invalid){r.bad=true;return;}
  auto hash=llvm::SHA256::hash(llvm::ArrayRef<uint8_t>((const uint8_t*)bytes.data(),bytes.size()));r.digest=llvm::toHex(hash,true);
  r.source_size=bytes.size();r.longlong=ci.getTarget().getLongLongWidth();
  r.target=ci.getTarget().getTriple().str();r.pointer=ci.getTarget().getPointerWidth(LangAS::Default);r.lng=ci.getTarget().getLongWidth();r.integer=ci.getTarget().getIntWidth();
  llvm::raw_string_ostream stream(r.ast);ctx.getTranslationUnitDecl()->dump(stream,false,ADOF_JSON);
 }
};
class Action : public ASTFrontendAction {
 Result &r;
 public: Action(Result &r):r(r){}
 bool BeginSourceFileAction(CompilerInstance &ci) override {ci.getPreprocessor().addPPCallbacks(std::make_unique<Callbacks>(ci.getSourceManager(),r));return true;}
 std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &ci,llvm::StringRef) override {return std::make_unique<Consumer>(ci,r);}
};
int main(int argc,char **argv) {
 if(argc!=5) return 2;
 unsigned major=0,minor=0,patch=0;LLVMGetVersion(&major,&minor,&patch);
 if(major!=19 || minor!=1 || patch!=7) return 2;
 Result result; llvm::IntrusiveRefCntPtr<FileManager> files(new FileManager(FileSystemOptions{}));
 std::vector<std::string> args={argv[1],"-x","c","-std=c11","-Werror","-fsyntax-only","-resource-dir",argv[2],"--target="+std::string(argv[3]),argv[4]};
 tooling::ToolInvocation invocation(args,std::make_unique<Action>(result),files.get());
 bool ok=invocation.run();
 if(!ok || result.bad || result.envelopes!=1 || result.ast.empty() || result.ast.size()>64*1024*1024) return 1;
 auto ast=llvm::json::parse(result.ast);if(!ast){llvm::consumeError(ast.takeError());return 1;}
 llvm::json::Object out{{"schema",1},{"compiler",getClangFullVersion()},{"target",result.target},{"pointer_bits",result.pointer},{"long_bits",result.lng},{"int_bits",result.integer},{"long_long_bits",result.longlong},{"source_size",result.source_size},{"source_sha256",result.digest},{"main_macro_expansions",std::move(result.events)},{"ast_json",result.ast}};
 llvm::outs()<<llvm::formatv("{0:2}\n",llvm::json::Value(std::move(out)));return 0;
}
