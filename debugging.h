// DPRINT() is a dumb little macro for debug print statements.

#pragma once

#include <string.h>
#include <stdio.h>

#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/Analysis/ProgramPoint.h"

using namespace clang;
using namespace ento;

// Turn off if you don't want ANSI term colors.
#if 1
#define RST  "\x1B[0m"
#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define BLU  "\x1B[34m"
#else
#define RST
#define RED
#define GRN
#define BLU
#endif

#define PRINT_PREFIX(func, file, line, code) fprintf(stderr, RED "%s" RST ":" GRN "%d" RST ":" BLU "%s()" RST " %s", file, line, func, code); fflush(stderr);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DPRINT(arg) debug_print(__func__, __FILENAME__, __LINE__, #arg, arg)

static inline const char *KindToStr(MemRegion::Kind K) {
  switch(K) {
    case MemRegion::CodeSpaceRegionKind: return "CodeSpaceRegion";
    case MemRegion::GlobalImmutableSpaceRegionKind: return "GlobalImmutableSpaceRegion";
    case MemRegion::GlobalInternalSpaceRegionKind: return "GlobalInternalSpaceRegion";
    case MemRegion::GlobalSystemSpaceRegionKind: return "GlobalSystemSpaceRegion";
    case MemRegion::StaticGlobalSpaceRegionKind: return "StaticGlobalSpaceRegion";
    case MemRegion::HeapSpaceRegionKind: return "HeapSpaceRegion";
    case MemRegion::StackArgumentsSpaceRegionKind: return "StackArgumentsSpaceRegion";
    case MemRegion::StackLocalsSpaceRegionKind: return "StackLocalsSpaceRegion";
    case MemRegion::UnknownSpaceRegionKind: return "UnknownSpaceRegion";
    case MemRegion::AllocaRegionKind: return "AllocaRegion";
    case MemRegion::SymbolicRegionKind: return "SymbolicRegion";
    case MemRegion::BlockDataRegionKind: return "BlockDataRegion";
    case MemRegion::BlockCodeRegionKind: return "BlockCodeRegion";
    case MemRegion::FunctionCodeRegionKind: return "FunctionCodeRegion";
    case MemRegion::CompoundLiteralRegionKind: return "CompoundLiteralRegion";
    case MemRegion::CXXBaseObjectRegionKind: return "CXXBaseObjectRegion";
    case MemRegion::CXXTempObjectRegionKind: return "CXXTempObjectRegion";
    case MemRegion::CXXThisRegionKind: return "CXXThisRegion";
    case MemRegion::FieldRegionKind: return "FieldRegion";
    case MemRegion::ObjCIvarRegionKind: return "ObjCIvarRegion";
    case MemRegion::VarRegionKind: return "VarRegion";
    case MemRegion::ElementRegionKind: return "ElementRegion";
    case MemRegion::ObjCStringRegionKind: return "ObjCStringRegion";
    case MemRegion::StringRegionKind: return "StringRegion";
  }

  return "Not found?!";
}

static inline const char *KindToStr(SymExpr::Kind K) {
  switch(K) {
    case SymExpr::IntSymExprKind: return "IntSymExpr";
    case SymExpr::SymIntExprKind: return "SymIntExpr";
    case SymExpr::SymSymExprKind: return "SymSymExpr";
    case SymExpr::SymbolConjuredKind: return "SymbolConjured";
    case SymExpr::SymbolCastKind: return "SymbolCast";
    case SymExpr::SymbolDerivedKind: return "SymbolDerived";
    case SymExpr::SymbolExtentKind: return "SymbolExtent";
    case SymExpr::SymbolMetadataKind: return "SymbolMetadata";
    case SymExpr::SymbolRegionValueKind: return "SymbolRegionValue";
  }

  return "Not found?!";
}

static inline const char *KindToStr(SVal::BaseKind K, unsigned subKind) {
  switch(K) {
    case SVal::UndefinedValKind: return "UndefinedValKind";
    case SVal::UnknownValKind: return "UnknownValKind";
    case SVal::NonLocKind:
      switch(subKind) {
        case nonloc::SymbolValKind: return "nonloc::SymbolValKind";
        case nonloc::ConcreteIntKind: return "nonloc::ConcreteIntKind";
        case nonloc::LocAsIntegerKind: return "nonloc::LocAsIntegerKind";
        case nonloc::CompoundValKind: return "nonloc::CompoundValKind";
        case nonloc::LazyCompoundValKind: return "nonloc::LazyCompoundValKind";
      }
      return "NonLocKind";
    case SVal::LocKind:
      switch(subKind) {
        case loc::GotoLabelKind: return "loc::GotoLabelKind";
        case loc::MemRegionValKind: return "loc::MemRegionValKind";
        case loc::ConcreteIntKind: return "loc::ConcreteIntKind";
      }
      return "LocKind";
  }
  
  return "Not found?!";
}

static inline const char *KindToStr(ProgramPoint::Kind K) {
  switch(K) {
    case ProgramPoint::BlockEdgeKind: return "BlockEdgeKind";
    case ProgramPoint::BlockEntranceKind: return "BlockEntranceKind";
    case ProgramPoint::BlockExitKind: return "BlockExitKind";
    case ProgramPoint::PreStmtKind: return "PreStmtKind";
    case ProgramPoint::PreStmtPurgeDeadSymbolsKind: return "PreStmtPurgeDeadSymbolsKind";
    case ProgramPoint::PostStmtPurgeDeadSymbolsKind: return "PostStmtPurgeDeadSymbolsKind";
    case ProgramPoint::PostStmtKind: return "PostStmtKind";
    case ProgramPoint::PreLoadKind: return "PreLoadKind";
    case ProgramPoint::PostLoadKind: return "PostLoadKind";
    case ProgramPoint::PreStoreKind: return "PreStoreKind";
    case ProgramPoint::PostStoreKind: return "PostStoreKind";
    case ProgramPoint::PostConditionKind: return "PostConditionKind";
    case ProgramPoint::PostLValueKind: return "PostLValueKind";
    case ProgramPoint::PostInitializerKind: return "PostInitializerKind";
    case ProgramPoint::CallEnterKind: return "CallEnterKind";
    case ProgramPoint::CallExitBeginKind: return "CallExitBeginKind";
    case ProgramPoint::CallExitEndKind: return "CallExitEndKind";
    case ProgramPoint::PreImplicitCallKind: return "PreImplicitCallKind";
    case ProgramPoint::PostImplicitCallKind: return "PostImplicitCallKind";
    case ProgramPoint::EpsilonKind: return "EpsilonKind";
  }

  return "Not found?!";
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const char *str)
{
  PRINT_PREFIX(func, file, line, str)
  fprintf(stderr, "\n");
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, size_t sz)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = %zu\n", sz);
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, bool boolean)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [bool] %s\n", boolean ? "true" : "false");
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const Type *Type)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [Type] ");
  fflush(stderr);
  if (Type)
    Type->dump();
  else
    fprintf(stderr, "(null)\n");
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, SymbolRef Sym)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [SymbolRef] ");
  if (Sym) {
    fflush(stderr);
    Sym->dump();
    fprintf(stderr, " (kind %s)\n", KindToStr(Sym->getKind()));
  } else
    fprintf(stderr, "(null)\n");
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const MemRegion *Reg)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [MemRegion] ");
  if (Reg)
    fprintf(stderr, "%s (kind %s)\n",
        Reg->getString().c_str(),
        KindToStr(Reg->getKind()));
  else
    fprintf(stderr, "(null)\n");
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const SVal S)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [SVal] ");
  fflush(stderr);
  S.dumpToStream(llvm::errs());
  fprintf(stderr, " (kind %s)\n", KindToStr(S.getBaseKind(), S.getSubKind()));
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const QualType QT)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [QualType] ");
  fflush(stderr);
  // TODO: Short version and then dump on the next line
  QT->dump();
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const Stmt *S)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [Stmt]");
  if (S) {
    fprintf(stderr, ":\n");
    fflush(stderr);
    S->dumpColor();
  } else {
    fprintf(stderr, " (null)");
  }
  fprintf(stderr, "\n");
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const ProgramPoint PP)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [ProgramPoint] ");
  if (PP.getTag())
    fprintf(stderr, "%s", PP.getTag()->getTagDescription().str().c_str());
  else
    fprintf(stderr, "(no tag)");
  fprintf(stderr, " (kind %s)\n", KindToStr(PP.getKind()));
  fflush(stderr);
}

static inline void debug_print(const char *func, const char *file, int line, const char *code, const FunctionDecl *FD)
{
  PRINT_PREFIX(func, file, line, code)
  fprintf(stderr, " = [FunctionDecl] ");
  if (FD) {
    fprintf(stderr, "'%s' with %u arg(s) and return type %s\n", FD->getIdentifier()->getNameStart(), FD->getMinRequiredArguments(), FD->getReturnType().getAsString().c_str());
  } else {
    fprintf(stderr, "(null)\n");
  }
  fflush(stderr);
}
