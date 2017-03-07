//===- KernelMemoryDisclosureChecker.cpp -------------------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines a kernel-to-user memory disclosure checker, which looks for
// instances where the kernel might copy uninitialized memory to userland,
// potentially leaking kernel memory. It identifies four types of potential
// memory disclosure flaws:
// 1) Copying structs with uncleared alignment padding
// 2) Copying structs with fields that have not been set
// 3) Copying struct fields or variables that were left partially uninitialized,
// e.g. if you strcpy(struct.field, "foo") the end of the field will be left
// uninitialized if struct.field is wider than 4 bytes
// 4) Copying unions (or union fields in structs) that have fields of different
// sizes that might have uninitialized memory
//
// TODO: Once FreeBSD bugs are fixed, reduce FPs by only alerting on memory
// regions on the stack or where the analyzer 'saw' the allocation for it.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/RecordLayout.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"

#ifdef __APPLE__
#include "clang/StaticAnalyzer/Checkers/MachInterface.h"
#endif

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
//#define DEBUG_PRINT

using namespace clang;
using namespace ento;

namespace {

class KernelMemoryDisclosureChecker
    : public Checker<
#ifdef __APPLE__
          check::BeginFunction, check::EndFunction,
#endif
          check::PreCall, check::PostCall, check::RegionChanges, check::Bind> {

  mutable std::unique_ptr<BugType> BTStructPadding, BTUnreferencedFields,
      BTUnsanitizedFields, BTUnionFieldSizes;

#ifdef __APPLE__
  // Maps XNU MIG functions to argument numbers for unlimited size arrays
  mutable std::multimap<const IdentifierInfo *, size_t> MachInterface;
#endif

  mutable llvm::SmallSet<const IdentifierInfo *, 32> FunctionWhitelist;
  mutable const IdentifierInfo *II_copyout, *II_sooptcopyout, *II_copy_to_user,
      *II___copy_to_user, *II_copyin, *II_sooptcopyin, *II_copy_from_user,
      *II___copy_from_user, *II_memdup_user, *II_malloc, *II_kzalloc,
      *II_kcalloc, *II_kmem_zalloc, *II___memset, *II_memset, *II_bzero,
      *II___memzero, *II___memcpy, *II_memcpy, *II_memmove, *II_bcopy,
      *II_strcpy, *II_strlcpy, *II_strncpy, *II_sprintf, *II_snprintf,
      *II_vm_map_copyin;

  void initInternalFields(ASTContext &Ctx) const;

  bool __hasUnevenUnionFields(CheckerContext &C, const MemRegion *MR,
                              const RecordDecl *RD) const;
  bool hasUnevenUnionFields(CheckerContext &C, const MemRegion *MR,
                            const RecordDecl *RD) const;
  void __isRegionPadded(ASTContext &Ctx, const RecordType *RT,
                        const RecordDecl *RD, bool *Padding) const;
  size_t isRegionPadded(ASTContext &Ctx, const RecordType *RT,
                        const RecordDecl *RD) const;
  bool isRegionSanitized(const MemRegion *MR, ProgramStateRef State) const;
  const MemRegion *isRegionUnsanitized(const MemRegion *MR,
                                       ProgramStateRef State,
                                       bool entireRegionCopied) const;
  void queryReferencedFields(CheckerContext &C, const MemRegion *MR,
                             const RecordDecl *RD, size_t *RefFields,
                             size_t *UnrefFields,
                             std::string &UnreferencedStr) const;

  void checkIfRegionUninitialized(CheckerContext &C, const MemRegion *MR,
                                  SVal Size, SourceRange SourceRange) const;
  void handleCopyout(const CallEvent &Call, CheckerContext &C, int SrcArg,
                     int SizeArg) const;
  void handleMemcopy(const CallEvent &Call, CheckerContext &C, int DstArg,
                     int SizeArg) const;
  void handleMalloc(const CallEvent &Call, CheckerContext &C) const;
  void sanitizeRetVal(const CallEvent &Call, CheckerContext &C) const;
  void sanitizeArg(const CallEvent &Call, CheckerContext &C, int Arg) const;
  void unsanitizeArg(const CallEvent &Call, CheckerContext &C, int Arg) const;

  // Bug visitor that prints additional information for 'partially sanitized'
  // field bugs, indicating the line where the partial sanitization takes place.
  class UnsanitizedBugVisitor
      : public BugReporterVisitorImpl<UnsanitizedBugVisitor> {
  private:
    const MemRegion *MR;

  public:
    UnsanitizedBugVisitor(const MemRegion *MR) : MR(MR) {}
    void Profile(llvm::FoldingSetNodeID &ID) const override { ID.Add(MR); }

    PathDiagnosticPiece *VisitNode(const ExplodedNode *N,
                                   const ExplodedNode *PrevN,
                                   BugReporterContext &BRC,
                                   BugReport &BR) override;
  };

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  ProgramStateRef
  checkRegionChanges(ProgramStateRef State, const InvalidatedSymbols *,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *>, const CallEvent *) const;
  bool wantsRegionChangeUpdate(ProgramStateRef) const { return true; }

#ifdef __APPLE__
  void checkBeginFunction(CheckerContext &C) const;
  void checkEndFunction(CheckerContext &C) const;
#endif
};

} // end anonymous namespace

// Regions that have not been fully initialized
REGISTER_SET_WITH_PROGRAMSTATE(UnsanitizedRegions, const MemRegion *);
// Regions that have been sanitized
REGISTER_SET_WITH_PROGRAMSTATE(SanitizedRegions, const MemRegion *);
// Symbols that have been sanitized
REGISTER_SET_WITH_PROGRAMSTATE(SanitizedSymbols, SymbolRef);
// Fields that have been initialized in a given region, e.g. a write to
// struct.f1.f2 would save pair<struct, f1> and pair<struct, f2> to note that
// those fields have been referenced/initialized.
// TODO: This fails with casts. e.g. if there is a struct info_v0 and info_v1
// where v0 is a subset of v1, if you write to ((struct info_v0*)v1).foo it will
// save a reference to a write to v1 field struct_info_v0.foo instead of
// struct_info_v1.foo and FP. This is not a frequent FP, so might not be worth
// fixing.
typedef std::pair<const MemRegion *, const FieldDecl *> FieldReference;
REGISTER_SET_WITH_PROGRAMSTATE(ReferencedFields, FieldReference);

#ifdef __APPLE__
// On XNU kernels, maps unlimited size array argument symbols to the memregions
// for which they have a binding (technically we could just use the RegionStore
// for this but I got tired of fighting with symbol reaping to make that work
// correctly.)
REGISTER_MAP_WITH_PROGRAMSTATE(MIGArraySymbols, SymbolRef, const MemRegion *);
#endif

void KernelMemoryDisclosureChecker::initInternalFields(ASTContext &Ctx) const {
  if (II_copyout)
    return;

  BTStructPadding.reset(
      new BugType(this, "Unsanitized struct padding", "Memory Disclosure"));
  BTUnreferencedFields.reset(
      new BugType(this, "Unreferenced struct element", "Memory Disclosure"));
  BTUnsanitizedFields.reset(new BugType(
      this, "Partially unsanitized struct element", "Memory Disclosure"));
  BTUnionFieldSizes.reset(
      new BugType(this, "Partially sanitized union (elements vary in size)",
                  "Memory Disclosure"));

#ifdef __APPLE__
  MachInterface.insert(
      std::make_pair(&Ctx.Idents.get("test_mach_interface"), 1));
  for (size_t i = 0; i < sizeof(mig_routines) / sizeof(mig_routines[0]); i++) {
    if (mig_routines[i].direction != OUT)
      continue;
    if (!mig_routines[i].is_unlimited_size_array)
      continue;

    IdentifierInfo *routine = &Ctx.Idents.get(mig_routines[i].routine);
    MachInterface.insert(std::make_pair(routine, mig_routines[i].idx));
  }
#endif

#define RESOLVE(function)                                                      \
  II_##function = &Ctx.Idents.get(#function);                                  \
  FunctionWhitelist.insert(II_##function);

  RESOLVE(copyout);
  RESOLVE(sooptcopyout)
  RESOLVE(copy_to_user)
  RESOLVE(__copy_to_user)
  RESOLVE(copyin)
  RESOLVE(sooptcopyin)
  RESOLVE(copy_from_user)
  RESOLVE(__copy_from_user)
  RESOLVE(memdup_user)
  RESOLVE(malloc)
  RESOLVE(kzalloc)
  RESOLVE(kcalloc)
  RESOLVE(kmem_zalloc)
  RESOLVE(__memset)
  RESOLVE(memset)
  RESOLVE(bzero)
  RESOLVE(__memzero)
  RESOLVE(__memcpy)
  RESOLVE(memcpy)
  RESOLVE(memmove)
  RESOLVE(bcopy)
  RESOLVE(strcpy)
  RESOLVE(strlcpy)
  RESOLVE(strncpy)
  RESOLVE(sprintf)
  RESOLVE(snprintf)
  RESOLVE(vm_map_copyin)

#undef RESOLVE
}

// Check if the union being checked has fields that are of different sizes, if
// there are fields of different sizes and the largest field(s) are not
// fully sanitized, indicate a possible memory disclosure.
bool KernelMemoryDisclosureChecker::__hasUnevenUnionFields(
    CheckerContext &C, const MemRegion *MR, const RecordDecl *RD) const {
  ASTContext &Ctx = C.getASTContext();
  ProgramStateRef State = C.getState();
  MemRegionManager &MRM = C.getSValBuilder().getRegionManager();

  bool DifferentSizedFields = false;
  auto GreatestFieldSize =
      Ctx.getTypeSizeInChars(RD->field_begin()->getType()).getQuantity();
  for (const FieldDecl *FD : RD->fields()) {
    auto CurSize = Ctx.getTypeSizeInChars(FD->getType()).getQuantity();
    if (CurSize != GreatestFieldSize)
      DifferentSizedFields = true;
    if (CurSize > GreatestFieldSize)
      GreatestFieldSize = CurSize;
  }

  if (!DifferentSizedFields)
    return false;

  // Check if one of the largest fields appear to be correctly sanitized
  for (const FieldDecl *FD : RD->fields()) {
    auto CurSize = Ctx.getTypeSizeInChars(FD->getType()).getQuantity();
    if (CurSize != GreatestFieldSize)
      continue;

    const MemRegion *UMR = MRM.getFieldRegion(FD, MR);
    if (!UMR)
      continue;

    if (State->contains<SanitizedRegions>(UMR))
      return false;

    const Type *UT = FD->getType().getTypePtrOrNull();
    if (!UT)
      continue;

    const RecordType *URT = UT->getAs<RecordType>();
    if (!URT)
      continue;

    const RecordDecl *URD = URT->getDecl();
    if (!URD)
      continue;

    std::string output;
    size_t RefCount, UnrefCount;
    queryReferencedFields(C, UMR, URD, &RefCount, &UnrefCount, output);

    if (!UnrefCount)
      return false;
  }

#ifdef DEBUG_PRINT
  printf("Uneven union %p: ", (void *)MR);
  fflush(stdout);
  RD->dump();
#endif

  return true;
}

// If MR is a union, or if a MR is a struct with an field that's a union, check
// it using __hasUnevenUnionFields
bool KernelMemoryDisclosureChecker::hasUnevenUnionFields(
    CheckerContext &C, const MemRegion *MR, const RecordDecl *RD) const {
  if (RD->isUnion())
    return __hasUnevenUnionFields(C, MR, RD);

  MemRegionManager &MRM = C.getSValBuilder().getRegionManager();
  for (const FieldDecl *FD : RD->fields()) {
    const Type *Type = FD->getType().getTypePtrOrNull();
    if (!Type)
      continue;

    const RecordType *URT = Type->getAsUnionType();
    if (!URT)
      continue;

    const RecordDecl *URD = URT->getDecl();
    if (!URD || URD->field_empty())
      continue;

    const MemRegion *UMR = MRM.getFieldRegion(FD, MR);
    if (!UMR)
      continue;

    if (__hasUnevenUnionFields(C, UMR, URD))
      return true;
  }

  return false;
}

// Loop through the fields in the given declaration and mark bytes that aren't
// padding in the 'Padding' array. This can run recursively to find padding in
// structs contained in structs.
void KernelMemoryDisclosureChecker::__isRegionPadded(ASTContext &Ctx,
                                                     const RecordType *RT,
                                                     const RecordDecl *RD,
                                                     bool *Padding) const {
  const ASTRecordLayout &RL = Ctx.getASTRecordLayout(RD);
  for (const FieldDecl *FD : RD->fields()) {
    size_t FieldOffset =
        Ctx.toCharUnitsFromBits(RL.getFieldOffset(FD->getFieldIndex()))
            .getQuantity();

// Turn this on to make it run recursively, will FP since it doesn't check
// against SanitizedRegions at the moment.
#if 0
    const Type *Type = FD->getType().getTypePtrOrNull();
    if (Type && (Type->isUnionType() || Type->isStructureType())) {
      // TODO: If it's in SanitizedRegions, don't run this (since the padding
      // has been cleared already) Source of FPs
      const RecordType *subRT = Type->getAsUnionType();
      if (!subRT)
        subRT = Type->getAsStructureType();
      if (subRT) {
        const RecordDecl *subRD = subRT->getDecl();
        if (subRD) {
          __isRegionPadded(Ctx, subRT, subRD, Padding + FieldOffset);
          continue;
        }
      }
    }
#endif

    size_t FieldSize = Ctx.getTypeSizeInChars(FD->getType()).getQuantity();
    memset(Padding + FieldOffset, 0, FieldSize);
  }
}

// Find padding in a type declaration and return the maximum number of bytes of
// contiguous padding present.
size_t KernelMemoryDisclosureChecker::isRegionPadded(
    ASTContext &Ctx, const RecordType *RT, const RecordDecl *RD) const {
  size_t TotalSize = Ctx.getTypeSizeInChars(RT).getQuantity();

  // Array of bools representing padding/not padding for every byte in the
  // struct/union, set all bytes to be padding to start.
  bool *Padding = new bool[TotalSize];
  memset(Padding, 1, TotalSize);

  __isRegionPadded(Ctx, RT, RD, Padding);

  size_t maxPadding = 0, curStreak = 0;
  for (size_t i = 0; i < TotalSize; i++) {
    if (!Padding[i]) {
      curStreak = 0;
    } else {
      curStreak++;
      maxPadding = MAX(maxPadding, curStreak);
    }
  }

#ifdef DEBUG_PRINT
  if (maxPadding) {
    printf("Following struct has %zu bytes max padding\n", maxPadding);
    RT->dump();
    for (size_t i = 0; i < TotalSize; i++) {
      if (i && !(i & 7))
        printf("\n");

      printf("%c", Padding[i] ? 'P' : '_');
    }
    printf("\n");
  }
#endif

  delete[] Padding;
  return maxPadding;
}

// Check if the memory region to be copied out has been sanitized, or is a
// sub-region of a sanitized region. Global variables are considered to always
// be sanitized.
bool KernelMemoryDisclosureChecker::isRegionSanitized(
    const MemRegion *MR, ProgramStateRef State) const {
  while (MR) {
    if (State->contains<SanitizedRegions>(MR) ||
        State->contains<SanitizedRegions>(MR->StripCasts()))
      return true;

    if (MR->getSymbolicBase() &&
        State->contains<SanitizedSymbols>(MR->getSymbolicBase()->getSymbol()))
      return true;

    const VarRegion *VR = MR->getAs<VarRegion>();
    if (VR) {
      const VarDecl *VD = VR->getDecl();
      if (VD && VD->hasGlobalStorage())
        return true;
    }

    const SubRegion *SR = MR->getAs<SubRegion>();
    if (!SR)
      break;

    MR = SR->getSuperRegion();
  }

  return false;
}

// Check if the region or a sub-region are marked 'unsanitized', e.g. if it
// has only been partially initialized.
// entireRegionCopied: If the entire region is unsanitized then it's likely a
// char buffer and the copyout() size argument might be something like
// strlen(buf) where sizeof(buf) < strlen(buf) would return TrueState=1
// FalseState=1. Avoid a slew of false positives by only signaling a partially
// unsanitized condition if we're sure the entire region is copied out.
const MemRegion *KernelMemoryDisclosureChecker::isRegionUnsanitized(
    const MemRegion *MR, ProgramStateRef State, bool entireRegionCopied) const {
  // Is the entire region marked unsanitized?
  if (State->contains<UnsanitizedRegions>(MR))
    return entireRegionCopied ? MR : NULL;

  if (State->contains<UnsanitizedRegions>(MR->StripCasts()))
    return entireRegionCopied ? MR->StripCasts() : NULL;

  // Loop over unsanitized regions and check whether they are a subregion
  UnsanitizedRegionsTy Regions = State->get<UnsanitizedRegions>();
  for (const MemRegion *Unsan : Regions) {
    const SubRegion *SR = Unsan->getAs<SubRegion>();
    if (SR && (SR->isSubRegionOf(MR) || SR->isSubRegionOf(MR->StripCasts())))
      return SR;
  }

  return NULL;
}

// Go through the struct/union and count the number of (un)referenced fields and
// save the names of the unreferenced fields.
void KernelMemoryDisclosureChecker::queryReferencedFields(
    CheckerContext &C, const MemRegion *MR, const RecordDecl *RD,
    size_t *RefFields, size_t *UnrefFields,
    std::string &UnreferencedStr) const {

  *RefFields = *UnrefFields = 0;

  // SymbolicRegion or VarRegion which this region is originally derives from
  const MemRegion *DerivedRegion = nullptr;
  const SubRegion *SR = MR->getAs<SubRegion>();
  while (SR) {
    if (SR->getKind() == MemRegion::SymbolicRegionKind ||
        SR->getKind() == MemRegion::VarRegionKind) {
      DerivedRegion = SR->StripCasts();
      break;
    }

    SR = SR->getSuperRegion()->getAs<SubRegion>();
  }

  if (!DerivedRegion)
    return;

  ProgramStateRef State = C.getState();
  ASTContext &Ctx = C.getASTContext();

  for (const FieldDecl *FD : RD->fields()) {
    if (Ctx.getTypeSizeInChars(FD->getType()).getQuantity() == 0)
      continue;

    if (State->contains<ReferencedFields>(std::make_pair(DerivedRegion, FD))) {
      *RefFields += 1;
    } else {
      if (*UnrefFields)
        UnreferencedStr += ", ";
      UnreferencedStr += FD->getNameAsString();

      *UnrefFields += 1;
    }

#ifdef DEBUG_PRINT
    printf("- Derived: %p / FD: %p / type: %s / Ref: %zu / Unref: %zu\n",
           (void *)DerivedRegion, (void *)FD,
           FD->getType().getAsString().c_str(), *RefFields, *UnrefFields);
#endif
  }
}

// Check if region MR with size Size is uninitialized. Used by handleCopyout()
// as well as the XNU MIG code in checkEndFunction()
void KernelMemoryDisclosureChecker::checkIfRegionUninitialized(
    CheckerContext &C, const MemRegion *MR, SVal Size,
    SourceRange SourceRange) const {
  ProgramStateRef State = C.getState();
  if (isRegionSanitized(MR, State))
    return;

  const TypedRegion *TR = MR->getAs<TypedRegion>();
  const Type *RegionType;
  if (TR) {
    RegionType = TR->getLocationType().getTypePtrOrNull();
  } else {
    // Work around for SymbolicRegions not being typed regions. Get the
    // underlying type.
    const SymbolicRegion *SymR = MR->getAs<SymbolicRegion>();
    if (!SymR)
      return;

    const MemRegion *underlyingMR = SymR->getSymbol()->getOriginRegion();
    if (!underlyingMR)
      return;

    const TypedRegion *underlyingTR = underlyingMR->getAs<TypedRegion>();
    if (!underlyingTR)
      return;

    const Type *underlyingType =
        underlyingTR->getLocationType().getTypePtrOrNull();
    if (!underlyingType || !underlyingType->isPointerType())
      return;

    RegionType = underlyingType->getPointeeType().getTypePtrOrNull();
  }

  if (!RegionType || !RegionType->isPointerType())
    return;

  // If less than the entire region is being copied out, we should skip any
  // disclosure checks since the disclosed memory might not be included

  // To find the size of the region, we want to avoid the case where references
  // to char buf[16] point to buf[0] and look like they have size 1. However,
  // we would like to keep references to struct_array[0]. (This is purely a
  // heuristic to avoid false positives.)
  const SubRegion *Uncast = MR->getAs<SubRegion>();
  const ElementRegion *ER = MR->getAs<ElementRegion>();
  if (ER) {
    const Type *EType = ER->getElementType().getTypePtrOrNull();
    if (EType && EType->isCharType())
      Uncast = MR->StripCasts()->getAs<SubRegion>();
  }

  SValBuilder &SVB = C.getSValBuilder();
  DefinedOrUnknownSVal RegionSize = Uncast->getExtent(SVB);
  DefinedOrUnknownSVal CopySize = Size.castAs<DefinedOrUnknownSVal>();

  bool entireRegionCopied = false;
  SVal Comparison =
      SVB.evalBinOp(State, BO_LT, CopySize, RegionSize, SVB.getConditionType());
  if (!Comparison.isUnknownOrUndef()) {
    ProgramStateRef TrueState, FalseState;
    std::tie(TrueState, FalseState) =
        State->assume(Comparison.castAs<DefinedSVal>());

    if (TrueState && !FalseState)
      return;

    entireRegionCopied = !TrueState && FalseState;
  }

  ExplodedNode *ErrorNode = NULL;
  if (const MemRegion *Unsan =
          isRegionUnsanitized(MR, State, entireRegionCopied)) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Copies out a struct with a partially unsanitized field";

    if (!ErrorNode)
      ErrorNode = C.generateNonFatalErrorNode(State);

    if (ErrorNode) {
      std::unique_ptr<BugReport> BR(
          new BugReport(*BTUnsanitizedFields, os.str(), ErrorNode));
      BR->addRange(SourceRange);
      BR->addVisitor(llvm::make_unique<UnsanitizedBugVisitor>(Unsan));
      C.emitReport(std::move(BR));
    }
  }

  const RecordType *RT = RegionType->getPointeeType()->getAs<RecordType>();
  if (!RT)
    return;

  const RecordDecl *RD = RT->getDecl();
  if (!RD)
    return;

  if (hasUnevenUnionFields(C, MR, RD)) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Copies out a struct with a union element with different sizes";

    if (!ErrorNode)
      ErrorNode = C.generateNonFatalErrorNode(State);

    if (ErrorNode) {
      std::unique_ptr<BugReport> BR(
          new BugReport(*BTUnionFieldSizes, os.str(), ErrorNode));
      BR->addRange(SourceRange);
      C.emitReport(std::move(BR));
    }
  }

  if (RT->isUnionType())
    return;

  size_t Padding = isRegionPadded(C.getASTContext(), RT, RD);
  if (Padding) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Copies out a struct with uncleared padding (>= " << Padding
       << " bytes)";

    if (!ErrorNode)
      ErrorNode = C.generateNonFatalErrorNode(State);

    if (ErrorNode) {
      std::unique_ptr<BugReport> BR(
          new BugReport(*BTStructPadding, os.str(), ErrorNode));
      BR->addRange(SourceRange);
      C.emitReport(std::move(BR));
    }
  }

  size_t RefCount, UnrefCount;
  std::string Unreferenced;
  queryReferencedFields(C, MR, RD, &RefCount, &UnrefCount, Unreferenced);

  // Check if every field in the struct has been referenced. Only warn on
  // unreferenced fields if some fields HAVE been referenced (e.g. ignore the
  // case where no fields of a struct have been written to at all since this is
  // likely a false positive due to the inability to inline a function.)
  // TODO: Alert on UnrefCount && MR in StackLocalSpaceRegion and no refs to
  // MR to non-inlined function args? checkPointerEscape??
  if (RefCount && UnrefCount) {
    SmallString<256> buf;
    llvm::raw_svector_ostream os(buf);
    os << "Copies out a struct with untouched element(s): " << Unreferenced;

    if (!ErrorNode)
      ErrorNode = C.generateNonFatalErrorNode(State);

    if (ErrorNode) {
      std::unique_ptr<BugReport> BR(
          new BugReport(*BTUnreferencedFields, os.str(), ErrorNode));
      BR->addRange(SourceRange);
      C.emitReport(std::move(BR));
    }
  }
}

// Check if the region to be copied to user space satisfies any of the memory
// disclosure criteria, report if it does.
void KernelMemoryDisclosureChecker::handleCopyout(const CallEvent &Call,
                                                  CheckerContext &C, int SrcArg,
                                                  int SizeArg) const {
  if (Call.getNumArgs() != 3)
    return;

  const MemRegion *MR = Call.getArgSVal(SrcArg).getAsRegion();
  if (!MR)
    return;

  SVal Size = Call.getArgSVal(SizeArg);
  checkIfRegionUninitialized(C, MR, Size, Call.getArgSourceRange(SrcArg));
}

// A memcpy()/memcpy-like function can either leave the destination region
// sanitized or partially unsanitized depending on whether the size argument is
// >= or < sizeof(region). Check which case it might be and mark the region
// sanitized/unsanitized depending on the result.
void KernelMemoryDisclosureChecker::handleMemcopy(const CallEvent &Call,
                                                  CheckerContext &C, int DstArg,
                                                  int SizeArg) const {
  const MemRegion *MR = Call.getArgSVal(DstArg).getAsRegion();
  if (!MR)
    return;

  const SubRegion *SR = MR->StripCasts()->getAs<SubRegion>();
  if (!SR)
    return;

  SValBuilder &SVB = C.getSValBuilder();
  ProgramStateRef State = C.getState();

  DefinedOrUnknownSVal CopySize =
      Call.getArgSVal(SizeArg).castAs<DefinedOrUnknownSVal>();
  DefinedOrUnknownSVal RegionSize = SR->getExtent(SVB);
  SVal Comparison =
      SVB.evalBinOp(State, BO_GE, CopySize, RegionSize, SVB.getConditionType());
  if (Comparison.isUnknownOrUndef())
    return;

  DefinedSVal condition = Comparison.castAs<DefinedSVal>();
  ProgramStateRef TrueState, FalseState;
  std::tie(TrueState, FalseState) = State->assume(condition);

  if (TrueState)
    State = State->add<SanitizedRegions>(SR);
  if (FalseState)
    State = State->add<UnsanitizedRegions>(SR);
  if (TrueState || FalseState)
    C.addTransition(State);
}

// On FreeBSD, malloc() returns a zero'ed region if the third argument (a
// bitfield) has the M_ZERO flag set. Mark the return value sanitized if this is
// the case.
void KernelMemoryDisclosureChecker::handleMalloc(const CallEvent &Call,
                                                 CheckerContext &C) const {
  if (Call.getNumArgs() != 3)
    return;

  const int M_ZERO = 0x0100;

  ProgramStateRef State = C.getState();
  QualType flags_type = Call.getArgExpr(2)->getType();
  NonLoc flags = Call.getArgSVal(2).castAs<NonLoc>();
  NonLoc zero_flag =
      C.getSValBuilder().makeIntVal(M_ZERO, flags_type).castAs<NonLoc>();
  SVal MaskedFlagsUC = C.getSValBuilder().evalBinOpNN(State, BO_And, flags,
                                                      zero_flag, flags_type);

  if (MaskedFlagsUC.isUnknownOrUndef())
    return;
  DefinedSVal MaskedFlags = MaskedFlagsUC.castAs<DefinedSVal>();

  // Check if maskedFlags is non-zero.
  ProgramStateRef TrueState, FalseState;
  std::tie(TrueState, FalseState) = State->assume(MaskedFlags);

  if (TrueState && !FalseState)
    sanitizeRetVal(Call, C);
}

// Mark the return value of this call sanitized.
void KernelMemoryDisclosureChecker::sanitizeRetVal(const CallEvent &Call,
                                                   CheckerContext &C) const {
  // Keep track of a SymbolRef instead of a MemRegion here because the region is
  // a SymbolicRegion and the address can change underneath us, e.g. if
  // MallocChecker runs after us it will modify the SVal/MemRegion returned by
  // malloc and hence future checks would fail, but the symbol stays the same so
  // we use that.
  SymbolRef Sym = Call.getReturnValue().getAsLocSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<SanitizedSymbols>(Sym);
  C.addTransition(State);
}

// Mark the 'Arg'th argument value of this call sanitized.
void KernelMemoryDisclosureChecker::sanitizeArg(const CallEvent &Call,
                                                CheckerContext &C,
                                                int Arg) const {
  const MemRegion *MR = Call.getArgSVal(Arg).getAsRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState()->add<SanitizedRegions>(MR->StripCasts());
  C.addTransition(State);
}

// Mark the 'Arg'th argument value of this call unsanitized, e.g. only
// partially initialized.
void KernelMemoryDisclosureChecker::unsanitizeArg(const CallEvent &Call,
                                                  CheckerContext &C,
                                                  int Arg) const {
  const MemRegion *MR = Call.getArgSVal(Arg).getAsRegion();
  if (!MR)
    return;

  ProgramStateRef State =
      C.getState()->add<UnsanitizedRegions>(MR->StripCasts());
  C.addTransition(State);
}

// Detect calls to copyout
void KernelMemoryDisclosureChecker::checkPreCall(const CallEvent &Call,
                                                 CheckerContext &C) const {
  initInternalFields(C.getASTContext());

  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

  if (FD->getIdentifier() == II_copyout)
    handleCopyout(Call, C, 0, 2);
  else if (FD->getIdentifier() == II_sooptcopyout ||
           FD->getIdentifier() == II_copy_to_user ||
           FD->getIdentifier() == II___copy_to_user)
    handleCopyout(Call, C, 1, 2);
}

// Detect calls to functions that taint (e.g. sanitize/unsanitize) their
// arguments or return values.
void KernelMemoryDisclosureChecker::checkPostCall(const CallEvent &Call,
                                                  CheckerContext &C) const {
  const FunctionDecl *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!FD)
    return;

#ifdef DEBUG_PRINT
  printf("=== ");
  fflush(stdout);
  Call.dump();

  for (unsigned int i = 0; i < Call.getNumArgs(); i++) {
    const MemRegion *MR = Call.getArgSVal(i).getAsRegion();
    printf("- Arg %i: MR = %p (%i), MR->StripCasts() = %p (%i)\n", i,
           (void *)MR, MR ? MR->getKind() : 0,
           MR ? (void *)MR->StripCasts() : NULL,
           MR ? MR->StripCasts()->getKind() : 0);
    fflush(stdout);
    Call.getArgSVal(i).dump();
    printf("\n");
    fflush(stdout);
  }
  printf("\n");
#endif

  if (!FunctionWhitelist.count(FD->getIdentifier()))
    return;
  else if (FD->getIdentifier() == II_memset ||
           FD->getIdentifier() == II___memset ||
           FD->getIdentifier() == II_bzero ||
           FD->getIdentifier() == II___memzero ||
           FD->getIdentifier() == II_copy_from_user ||
           FD->getIdentifier() == II___copy_from_user)
    sanitizeArg(Call, C, 0);
  else if (FD->getIdentifier() == II_copyin ||
           FD->getIdentifier() == II_sooptcopyin)
    sanitizeArg(Call, C, 1);
  else if (FD->getIdentifier() == II_kzalloc ||
           FD->getIdentifier() == II_kcalloc ||
           FD->getIdentifier() == II_kmem_zalloc ||
           FD->getIdentifier() == II_memdup_user)
    sanitizeRetVal(Call, C);
  else if (FD->getIdentifier() == II_strlcpy ||
           FD->getIdentifier() == II_strcpy ||
           FD->getIdentifier() == II_sprintf ||
           FD->getIdentifier() == II_snprintf)
    unsanitizeArg(Call, C, 0);
  else if (FD->getIdentifier() == II_memcpy ||
           FD->getIdentifier() == II___memcpy ||
           FD->getIdentifier() == II_memmove ||
           FD->getIdentifier() == II_strncpy)
    handleMemcopy(Call, C, 0, 2);
  else if (FD->getIdentifier() == II_bcopy)
    handleMemcopy(Call, C, 1, 2);
  else if (FD->getIdentifier() == II_malloc)
    handleMalloc(Call, C);
#ifdef __APPLE__
  else if (FD->getIdentifier() == II_vm_map_copyin) {
    ProgramStateRef State = C.getState();
    SVal Loc = Call.getArgSVal(4);
    SVal Val = Call.getArgSVal(1);
    State = State->bindLoc(Loc, Val);
    if (State->get<MIGArraySymbols>(Loc.getAsSymbol()))
      State = State->set<MIGArraySymbols>(Loc.getAsSymbol(), Val.getAsRegion());
    C.addTransition(State);
  }
#endif
}

// TODO: Copy over referenced/sanitized/unsanitized flags instead of doing
// a blanket sanitize here?
// When a region is directly written to, e.g. foo.bar = baz, assume it's
// sanitized correctly, e.g. that baz is fully initialized
void KernelMemoryDisclosureChecker::checkBind(SVal Loc, SVal Val, const Stmt *S,
                                              CheckerContext &C) const {
  const MemRegion *MR = Loc.getAsRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<SanitizedRegions>(MR->StripCasts());

#ifdef __APPLE__
  if (State->get<MIGArraySymbols>(Loc.getAsSymbol()))
    State = State->set<MIGArraySymbols>(Loc.getAsSymbol(), Val.getAsRegion());
#endif

  C.addTransition(State);
}

// When a region might change due to a direct write or having it's address
// passed to a function, if it's a field in a struct/union, mark those fields
// referenced for that variable
ProgramStateRef KernelMemoryDisclosureChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *,
    ArrayRef<const MemRegion *> ExplicitRegions, ArrayRef<const MemRegion *>,
    const CallEvent *) const {
  for (const MemRegion *MR : ExplicitRegions) {
    const SubRegion *SR = MR->getAs<SubRegion>();
    if (!SR)
      continue;

    llvm::SmallVector<const FieldDecl *, 16> fieldReferenceList;
    while (SR) {
      if (SR->getKind() == MemRegion::FieldRegionKind)
        fieldReferenceList.push_back(SR->getAs<FieldRegion>()->getDecl());

      if (SR->getKind() == MemRegion::SymbolicRegionKind ||
          SR->getKind() == MemRegion::VarRegionKind) {
        for (const FieldDecl *field : fieldReferenceList)
          State = State->add<ReferencedFields>(
              std::make_pair(SR->StripCasts(), field));
      }

      SR = SR->getSuperRegion()->getAs<SubRegion>();
    }
  }

  return State;
}

#ifdef __APPLE__
// If this function is a MIG function with unlimited size array OUT arguments,
// initialize them in MIGArraySymbols
void KernelMemoryDisclosureChecker::checkBeginFunction(
    CheckerContext &C) const {
  initInternalFields(C.getASTContext());

  const auto *LCtx = C.getLocationContext();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  const size_t OutArgs = MachInterface.count(FD->getIdentifier());
  if (!OutArgs)
    return;

  ProgramStateRef State = C.getState();
  ArrayRef<ParmVarDecl *> parameters = FD->parameters();

  std::multimap<const IdentifierInfo *, size_t>::const_iterator Args =
      MachInterface.find(FD->getIdentifier());
  for (size_t i = 0; i < OutArgs; i++, Args++) {
    size_t argIndex = Args->second;
    if (argIndex >= parameters.size())
      // TODO: Warn or error out?
      continue;

    const ParmVarDecl *PVD = parameters[argIndex];
    Loc ArgLoc = State->getLValue(PVD, LCtx);
    SVal Arg = State->getSVal(ArgLoc);

    State = State->set<MIGArraySymbols>(Arg.getAsSymbol(), NULL);
  }

  C.addTransition(State);
}

// If this is an XNU MIG function with an unlimited size array OUT argument,
// check if it might have leaked any uninitialized data.
void KernelMemoryDisclosureChecker::checkEndFunction(CheckerContext &C) const {
  const auto *LCtx = C.getLocationContext();
  const FunctionDecl *FD = dyn_cast<FunctionDecl>(LCtx->getDecl());
  if (!FD)
    return;

  const size_t OutArgs = MachInterface.count(FD->getIdentifier());
  if (!OutArgs)
    return;

  ProgramStateRef State = C.getState();
  ArrayRef<ParmVarDecl *> parameters = FD->parameters();

  // Iterate over all OUT arguments
  std::multimap<const IdentifierInfo *, size_t>::const_iterator Args =
      MachInterface.find(FD->getIdentifier());
  for (size_t i = 0; i < OutArgs; i++, Args++) {
    size_t argIndex = Args->second;
    if (argIndex >= parameters.size())
      continue;

    const ParmVarDecl *PVD = parameters[argIndex];
    Loc ArgLoc = State->getLValue(PVD, LCtx);
    SVal Arg = State->getSVal(ArgLoc);

    const MemRegion *MR = NULL;
    if (auto Var = State->get<MIGArraySymbols>(Arg.getAsSymbol())) {
      MR = *Var;
      State = State->remove<MIGArraySymbols>(Arg.getAsSymbol());
    }

    if (!MR)
      continue;

    // Check to see if the arg is uninitialized (when the call returns to
    // another translation unit it will be copied back to user space.)
    checkIfRegionUninitialized(C, MR, UnknownVal(), PVD->getSourceRange());
  }

  C.addTransition(State);
}
#endif

// Walk backwards from the copyout() to the point where the unsanitized region
// was marked and indicate it in the output
PathDiagnosticPiece *
KernelMemoryDisclosureChecker::UnsanitizedBugVisitor::VisitNode(
    const ExplodedNode *N, const ExplodedNode *PrevN, BugReporterContext &BRC,
    BugReport &BR) {

  if (!N->getState()->contains<UnsanitizedRegions>(MR) &&
      !N->getState()->contains<UnsanitizedRegions>(MR->StripCasts()))
    return nullptr;

  if (PrevN->getState()->contains<UnsanitizedRegions>(MR) ||
      PrevN->getState()->contains<UnsanitizedRegions>(MR->StripCasts()))
    return nullptr;

  PathDiagnosticLocation Location =
      PathDiagnosticLocation::create(N->getLocation(), BRC.getSourceManager());
  if (!Location.isValid() || !Location.asLocation().isValid())
    return nullptr;

  return new PathDiagnosticEventPiece(Location,
                                      "Partial initialization occurs here");
}

void ento::registerKernelMemoryDisclosureChecker(CheckerManager &mgr) {
  mgr.registerChecker<KernelMemoryDisclosureChecker>();
}
