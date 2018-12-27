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
// sizes where space was left uninitialized.
//
//===----------------------------------------------------------------------===//

#include "clang/AST/ParentMap.h"
#include "clang/AST/RecordLayout.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
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

  // Set of the functions below to quickly check if it's one of interest.
  mutable llvm::SmallSet<const IdentifierInfo *, 32> FunctionWhitelist;
  mutable const IdentifierInfo *II_copyout, *II_sooptcopyout, *II_copy_to_user,
      *II___copy_to_user, *II_copyin, *II_sooptcopyin, *II_copy_from_user,
      *II___copy_from_user, *II_malloc, *II_kmem_alloc, *II_kmalloc,
      *II_kmalloc_array, *II_sock_kmalloc, *II_kalloc, *II___MALLOC,
      *II___memset, *II_memset, *II_bzero, *II___memzero, *II___memcpy,
      *II_memcpy, *II_memmove, *II_bcopy, *II_strcpy, *II_strlcpy, *II_strncpy,
      *II_sprintf, *II_snprintf, *II_vm_map_copyin;

  void initInternalFields(ASTContext &Ctx) const;

  // Check if the union being checked has fields that are of different sizes, if
  // there are fields of different sizes and the largest field(s) are not fully
  // sanitized, indicate a possible memory disclosure.
  bool __hasUnevenUnionFields(CheckerContext &C, const SubRegion *SR,
                              const RecordDecl *RD) const;
  // If MR is a union, or if a MR is a struct with an field that's a union,
  // check it using __hasUnevenUnionFields
  bool hasUnevenUnionFields(CheckerContext &C, const MemRegion *MR,
                            const RecordDecl *RD) const;
  // Loop through the fields in the given declaration and mark bytes that aren't
  // padding in the 'Padding' array. This can run recursively to find padding in
  // structs contained in structs.
  void __isRegionPadded(ASTContext &Ctx, const RecordType *RT,
                        const RecordDecl *RD, bool *Padding) const;
  // Find padding in a type declaration and return the maximum number of bytes
  // of contiguous padding present.
  size_t isRegionPadded(ASTContext &Ctx, const RecordType *RT,
                        const RecordDecl *RD) const;
  // Check if the memory region to be copied out has been sanitized, or is a
  // sub-region of a sanitized region. Global variables are considered to always
  // be sanitized.
  bool isRegionSanitized(const MemRegion *MR, ProgramStateRef State) const;
  // Check if the region or a sub-region are marked 'unsanitized', e.g. if it
  // has only been partially initialized.
  // \param entireRegionCopied: If the entire region is unsanitized then it's
  // likely a char buffer and the copyout() size argument might be something
  // like/ strlen(buf) where sizeof(buf) < strlen(buf) would return TrueState=1
  // FalseState=1. Avoid a slew of false positives by only signaling a partially
  // unsanitized condition if we're sure the entire region is copied out.
  const MemRegion *isRegionUnsanitized(const MemRegion *MR,
                                       ProgramStateRef State,
                                       bool entireRegionCopied) const;
  // Go through the struct/union and count the number of (un)referenced fields
  // and save the names of the unreferenced fields.
  void queryReferencedFields(CheckerContext &C, const MemRegion *MR,
                             const RecordDecl *RD, size_t *RefFields,
                             size_t *UnrefFields,
                             std::string &UnreferencedStr) const;

  // Check if region MR with size Size is uninitialized. Used by handleCopyout()
  // as well as the XNU MIG code in checkEndFunction()
  void checkIfRegionUninitialized(CheckerContext &C, const MemRegion *MR,
                                  SVal Size, SourceRange SourceRange) const;
  // Check if the region to be copied to user space satisfies any of the memory
  // disclosure criteria, report if it does.
  void handleCopyout(const CallEvent &Call, CheckerContext &C, int SrcArg,
                     int SizeArg) const;
  // A memcpy()/memcpy-like function can either leave the destination region
  // sanitized or partially unsanitized depending on whether the size argument
  // is >= or < sizeof(region). Check which case it might be and mark the region
  // sanitized/unsanitized depending on the result.
  void handleMemcopy(const CallEvent &Call, CheckerContext &C, int DstArg,
                     int SizeArg) const;
  // Check if a given bit is set in a call argument. Used to check if the
  // M_ZERO flag was set to determine if a malloc() call returned a sanitized
  // region.
  bool argBitSet(const CallEvent &Call, CheckerContext &C, size_t Arg,
                 size_t Flag) const;
  // Mark the return value of this call a malloc()ed region.
  void mallocRetVal(const CallEvent &Call, CheckerContext &C) const;
  // Mark the contents of a given argument of this call a malloc()ed region.
  void mallocArg(const CallEvent &Call, CheckerContext &C, size_t Arg) const;
  // Mark the given argument value of this call sanitized.
  void sanitizeArg(const CallEvent &Call, CheckerContext &C, int Arg) const;
  // Mark the given argument value of this call unsanitized, e.g. only
  // partially initialized.
  void unsanitizeArg(const CallEvent &Call, CheckerContext &C, int Arg) const;

  // Bug visitor that prints additional information for 'partially sanitized'
  // field bugs, indicating the line where the partial sanitization takes place.
  class UnsanitizedBugVisitor final : public BugReporterVisitor {
  private:
    const MemRegion *MR;

  public:
    UnsanitizedBugVisitor(const MemRegion *MR) : MR(MR) {}
    void Profile(llvm::FoldingSetNodeID &ID) const override { ID.Add(MR); }

    // Walk backwards from the copyout() to the point where the unsanitized
    // region was marked and indicate it in the output
    std::shared_ptr<PathDiagnosticPiece> VisitNode(const ExplodedNode *N,
                                                   BugReporterContext &BRC,
                                                   BugReport &BR) override;
  };

public:
  // Detect calls to copyout
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  // Detect calls to functions that taint (e.g. sanitize/unsanitize) their
  // arguments or return values.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  // When a region is directly written to, e.g. foo.bar = baz, assume it's
  // sanitized correctly, e.g. that baz is fully initialized
  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const;
  // When a region might change due to a direct write or having it's address
  // passed to a function, if it's a field in a struct/union, mark those fields
  // referenced for that variable
  ProgramStateRef
  checkRegionChanges(ProgramStateRef State, const InvalidatedSymbols *,
                     ArrayRef<const MemRegion *> ExplicitRegions,
                     ArrayRef<const MemRegion *>, const LocationContext *,
                     const CallEvent *) const;
  bool wantsRegionChangeUpdate(ProgramStateRef) const { return true; }

#ifdef __APPLE__
  // If this function is a MIG function with unlimited size array OUT arguments,
  // initialize them in MIGArraySymbols
  void checkBeginFunction(CheckerContext &C) const;
  // If this is an XNU MIG function with an unlimited size array OUT argument,
  // check if it might have leaked any uninitialized data.
  void checkEndFunction(const ReturnStmt *RS, CheckerContext &C) const;
#endif
};

} // end anonymous namespace

// Regions that have not been fully initialized
REGISTER_SET_WITH_PROGRAMSTATE(UnsanitizedRegions, const MemRegion *)
// Regions that have been sanitized
REGISTER_SET_WITH_PROGRAMSTATE(SanitizedRegions, const MemRegion *)
// Symbols that were dynamically allocated and not cleared (used for heuristic
// to reject FPs on region that we didn't see allocated)
REGISTER_SET_WITH_PROGRAMSTATE(MallocedSymbols, SymbolRef)
// Fields that have been initialized in a given region, e.g. a write to
// struct.f1.f2 would save pair<struct, f1> and pair<struct, f2> to note that
// those fields have been referenced/initialized.
// TODO: This fails with casts. e.g. if there is a struct info_v0 and info_v1
// where v0 is a subset of v1, if you write to ((struct info_v0*)v1).foo it will
// save a reference to a write to v1 field struct_info_v0.foo instead of
// struct_info_v1.foo and FP. This is not a frequent FP, so might not be worth
// fixing.
typedef std::pair<const MemRegion *, const FieldDecl *> FieldReference;
REGISTER_SET_WITH_PROGRAMSTATE(ReferencedFields, FieldReference)

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
  RESOLVE(malloc)
  RESOLVE(kmem_alloc)
  RESOLVE(kmalloc)
  RESOLVE(kmalloc_array)
  RESOLVE(sock_kmalloc)
  RESOLVE(kalloc)
  // TODO: kalloc_canblock on XNU
  RESOLVE(__MALLOC)
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

bool KernelMemoryDisclosureChecker::__hasUnevenUnionFields(
    CheckerContext &C, const SubRegion *SR, const RecordDecl *RD) const {
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

    const MemRegion *UMR = MRM.getFieldRegion(FD, SR);
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
  printf("Uneven union %p: ", (const void *)SR);
  fflush(stdout);
  RD->dump();
#endif

  return true;
}

bool KernelMemoryDisclosureChecker::hasUnevenUnionFields(
    CheckerContext &C, const MemRegion *MR, const RecordDecl *RD) const {
  const SubRegion *SR = MR->getAs<SubRegion>();
  if (!SR)
    llvm::report_fatal_error("MemRegion unexpectedly not a SubRegion");

  if (RD->isUnion())
    return __hasUnevenUnionFields(C, SR, RD);

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

    const MemRegion *UMR = MRM.getFieldRegion(FD, SR);
    if (!UMR)
      continue;

    const SubRegion *USR = UMR->getAs<SubRegion>();
    if (!USR)
      continue;

    if (__hasUnevenUnionFields(C, USR, URD))
      return true;
  }

  return false;
}

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
      maxPadding = std::max(maxPadding, curStreak);
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

bool KernelMemoryDisclosureChecker::isRegionSanitized(
    const MemRegion *MR, ProgramStateRef State) const {

  // HEURISTIC: If this region is not on the stack and we did not see an
  // explicit dynamic allocation for it, consider it sanitized (this cuts down
  // of many FPs where we did not see the region initialized/sanitized, but
  // cuts down some TPs too)
  bool sanitizedStorage = !MR->hasStackNonParametersStorage();

  while (MR) {
    if (State->contains<SanitizedRegions>(MR) ||
        State->contains<SanitizedRegions>(MR->StripCasts()))
      return true;

    if (MR->getSymbolicBase() &&
        State->contains<MallocedSymbols>(MR->getSymbolicBase()->getSymbol()))
      sanitizedStorage = false;

    const SubRegion *SR = MR->getAs<SubRegion>();
    if (!SR)
      break;

    MR = SR->getSuperRegion();
  }

  return sanitizedStorage;
}

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
           (const void *)DerivedRegion, (const void *)FD,
           FD->getType().getAsString().c_str(), *RefFields, *UnrefFields);
#endif
  }
}

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

    SymbolRef Sym = SymR->getSymbol();
    if (const SymbolConjured *SC = dyn_cast<SymbolConjured>(Sym)) {
      RegionType = SC->getType().getTypePtrOrNull();
    } else {
      const MemRegion *underlyingMR = Sym->getOriginRegion();
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

  // Heuristic: Check if every struct field has been referenced. Only warn on
  // unreferenced fields if more fields HAVE been referenced (e.g. ignore the
  // case where no fields of a struct have been written to at all, or the vast
  // majority have not been since these are likely false positives due to the
  // inability to inline a function.)
  // TODO: Alert even if there are no referenced regions if it never pointer
  // escaped instead of this hacky heuristic
  if (UnrefCount && RefCount >= UnrefCount) {
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

bool KernelMemoryDisclosureChecker::argBitSet(const CallEvent &Call,
                                              CheckerContext &C, size_t Arg,
                                              size_t Flag) const {
  if (Call.getNumArgs() <= Arg)
    return false;

  ProgramStateRef State = C.getState();
  QualType flags_type = Call.getArgExpr(Arg)->getType();
  NonLoc flags = Call.getArgSVal(Arg).castAs<NonLoc>();
  NonLoc zero_flag =
      C.getSValBuilder().makeIntVal(Flag, flags_type).castAs<NonLoc>();
  SVal MaskedFlagsUC = C.getSValBuilder().evalBinOpNN(State, BO_And, flags,
                                                      zero_flag, flags_type);

  if (MaskedFlagsUC.isUnknownOrUndef())
    return false;
  DefinedSVal MaskedFlags = MaskedFlagsUC.castAs<DefinedSVal>();

  // Check if maskedFlags is non-zero.
  ProgramStateRef TrueState, FalseState;
  std::tie(TrueState, FalseState) = State->assume(MaskedFlags);
  return TrueState && !FalseState;
}

void KernelMemoryDisclosureChecker::mallocRetVal(const CallEvent &Call,
                                                 CheckerContext &C) const {
  SymbolRef Sym = Call.getReturnValue().getAsLocSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  State = State->add<MallocedSymbols>(Sym);
  C.addTransition(State);
}

void KernelMemoryDisclosureChecker::mallocArg(const CallEvent &Call,
                                              CheckerContext &C,
                                              size_t Arg) const {
  Optional<Loc> ArgLoc = Call.getArgSVal(Arg).getAs<Loc>();
  if (!ArgLoc)
    return;

  ProgramStateRef State = C.getState();
  SymbolRef Sym = State->getSVal(*ArgLoc).getAsLocSymbol();
  if (!Sym)
    return;

  State = State->add<MallocedSymbols>(Sym);
  C.addTransition(State);
}

void KernelMemoryDisclosureChecker::sanitizeArg(const CallEvent &Call,
                                                CheckerContext &C,
                                                int Arg) const {
  const MemRegion *MR = Call.getArgSVal(Arg).getAsRegion();
  if (!MR)
    return;

  ProgramStateRef State = C.getState()->add<SanitizedRegions>(MR->StripCasts());
  C.addTransition(State);
}

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
           (const void *)MR, MR ? MR->getKind() : 0,
           MR ? (const void *)MR->StripCasts() : NULL,
           MR ? MR->StripCasts()->getKind() : 0);
    fflush(stdout);
    Call.getArgSVal(i).dump();
    printf("\n");
    fflush(stdout);
  }
  printf("\n");
#endif

  // Various constants we need to check whether dynamically allocated memory is
  // zero'ed/sanitized.
  const int Linux_GFP_ZERO = 0x8000;
  const int FreeBSD_M_ZERO = 0x0100;
  const int XNU_M_ZERO = 0x04;

  const IdentifierInfo *Callee = FD->getIdentifier();
  if (!FunctionWhitelist.count(Callee))
    return;
  else if (Callee == II_memset || Callee == II___memset || Callee == II_bzero ||
           Callee == II___memzero || Callee == II_copy_from_user ||
           Callee == II___copy_from_user)
    sanitizeArg(Call, C, 0);
  else if (Callee == II_copyin || Callee == II_sooptcopyin)
    sanitizeArg(Call, C, 1);
  else if (Callee == II_strlcpy || Callee == II_strcpy ||
           Callee == II_sprintf || Callee == II_snprintf)
    unsanitizeArg(Call, C, 0);
  else if (Callee == II_memcpy || Callee == II___memcpy ||
           Callee == II_memmove || Callee == II_strncpy)
    handleMemcopy(Call, C, 0, 2);
  else if (Callee == II_bcopy)
    handleMemcopy(Call, C, 1, 2);
  else if (Callee == II_kmem_alloc || Callee == II_kalloc)
    mallocRetVal(Call, C);
  else if (Callee == II_kmalloc) {
    if (!argBitSet(Call, C, 1, Linux_GFP_ZERO))
      mallocRetVal(Call, C);
  } else if (Callee == II_sock_kmalloc || Callee == II_kmalloc_array) {
    if (!argBitSet(Call, C, 2, Linux_GFP_ZERO))
      mallocRetVal(Call, C);
  } else if (Callee == II_malloc) {
    if (!argBitSet(Call, C, 2, FreeBSD_M_ZERO))
      mallocRetVal(Call, C);
  } else if (Callee == II___MALLOC) {
    if (!argBitSet(Call, C, 2, XNU_M_ZERO))
      mallocArg(Call, C, 3);
  }
#ifdef __APPLE__
  else if (Callee == II_vm_map_copyin) {
    ProgramStateRef State = C.getState();
    SVal L = Call.getArgSVal(4);
    SVal Val = Call.getArgSVal(1);
    State = State->bindLoc(L, Val, C.getLocationContext());
    if (State->get<MIGArraySymbols>(L.getAsSymbol()))
      State = State->set<MIGArraySymbols>(L.getAsSymbol(), Val.getAsRegion());

    // TODO: Hack to prevent this symbol being marked sanitized in
    // isRegionSanitized() due to heuristic
    if (Optional<Loc> _L = L.getAs<Loc>())
      State = State->add<MallocedSymbols>(State->getSVal(*_L).getAsSymbol());

    C.addTransition(State);
  }
#endif
}

// TODO: Copy over referenced/sanitized/unsanitized flags instead of doing
// a blanket sanitize here?
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

ProgramStateRef KernelMemoryDisclosureChecker::checkRegionChanges(
    ProgramStateRef State, const InvalidatedSymbols *,
    ArrayRef<const MemRegion *> ExplicitRegions,
    ArrayRef<const MemRegion *> Regions, const LocationContext *LCtx,
    const CallEvent *CE) const {
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

void KernelMemoryDisclosureChecker::checkEndFunction(const ReturnStmt *RS,
                                                     CheckerContext &C) const {
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

std::shared_ptr<PathDiagnosticPiece>
KernelMemoryDisclosureChecker::UnsanitizedBugVisitor::VisitNode(
    const ExplodedNode *N, BugReporterContext &BRC, BugReport &BR) {
  const ExplodedNode *PrevN = N->getFirstPred();

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

  return std::make_shared<PathDiagnosticEventPiece>(
      Location, "Partial initialization occurs here");
}

void ento::registerKernelMemoryDisclosureChecker(CheckerManager &mgr) {
  mgr.registerChecker<KernelMemoryDisclosureChecker>();
}
