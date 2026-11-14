/* SPDX-License-Identifier: BSD-2-Clause */
#include <Library/OppoMemoryPlanLib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static OPPO_BOOT_HANDOFF fixture(void)
{
  OPPO_BOOT_HANDOFF info = {0};
  info.Ram[0] = (OPPO_MEMORY_RANGE){0x40000000, 0x180000000ULL}; info.RamCount = 1;
  info.Reserved[0] = (OPPO_MEMORY_RANGE){0x78800000, 0x5800000};
  info.ReservedFlags[0] = OPPO_RESERVATION_NO_MAP;
  info.Reserved[1] = (OPPO_MEMORY_RANGE){0x57300000, 0x3a615};
  info.ReservedFlags[1] = OPPO_RESERVATION_BOOT_DATA;
  info.ReservedCount = 2; info.FdtPhysicalAddressRecorded = TRUE;
  info.DynamicReservationCount = 6; info.EmptyReservationNodeCount = 1;
  return info;
}

static void synthetic(void)
{
  OPPO_BOOT_HANDOFF info = fixture(), changed;
  OPPO_EARLY_MEMORY_PLAN plan, before;
  OPPO_MEMORY_RANGE image = {0x40080000, 0x800000}, pool = {0x43000000, 0x4000000};
  assert(OppoPlanEarlyMemory(&info, image, pool, FALSE, &plan) == EFI_SUCCESS);
  assert(plan.ProtectedCount == 3 && plan.DynamicReservationsDeferredToOs == 6 && plan.EmptyNodesIgnored == 1);
  assert(plan.Protected[1].Base == 0x57300000 && plan.Protected[1].Length == 0x3b000);
  assert(plan.ProtectedType[0] == EfiReservedMemoryType && plan.ProtectedType[1] == EfiBootServicesData);
  assert(plan.ProtectedType[2] == EfiBootServicesCode);
  before = plan;
  for (UINTN i = 0; i < 7; i++) {
    changed = info;
    if (i == 0) changed.UnresolvedReservationCount = 1;
    if (i == 1) changed.FdtPhysicalAddressRecorded = FALSE;
    if (i == 2) changed.Reserved[0] = pool;
    if (i == 3) changed.Reserved[1].Base = MAX_UINT64 - 4096;
    if (i == 4) changed.ReservedCount = OPPO_MAX_BOOT_RESERVATIONS + 1;
    if (i == 5) changed.Reserved[1].Base = changed.Reserved[0].Base + 1;
    if (i == 6) changed.ReservedFlags[0] = 0x80000000;
    assert(OppoPlanEarlyMemory(&changed, image, pool, FALSE, &plan) != EFI_SUCCESS);
    assert(memcmp(&plan, &before, sizeof plan) == 0);
  }
  OPPO_MEMORY_RANGE bad[] = {{0x43000001, 0x4000000}, {0x43000000, 4096}, {0x40080000, 0x4000000},
                            {0x200000000ULL, 0x4000000}, {MAX_UINT64 - 4095, 0x4000000}};
  for (UINTN i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    assert(OppoPlanEarlyMemory(&info, image, bad[i], FALSE, &plan) != EFI_SUCCESS);
    assert(memcmp(&plan, &before, sizeof plan) == 0);
  }
  // Page rounding, not raw byte adjacency, defines the exclusion boundary.
  changed = info;
  changed.Reserved[2] = (OPPO_MEMORY_RANGE){0x5733a616, 1}; changed.ReservedCount = 3;
  assert(OppoPlanEarlyMemory(&changed, image, pool, FALSE, &plan) == EFI_COMPROMISED_DATA);
}

static void acpi_reservation_ownership(void)
{
  OPPO_BOOT_HANDOFF info = fixture();
  OPPO_EARLY_MEMORY_PLAN dt, acpi;
  OPPO_MEMORY_RANGE image = {0x40080000, 0x800000};
  OPPO_MEMORY_RANGE pool = {0x43000000, 0x4000000};
  info.Reserved[2] = (OPPO_MEMORY_RANGE){0x7fbc0000, 0x40000};
  info.ReservedCount = 3;

  assert(OppoPlanEarlyMemory(&info, image, pool, FALSE, &dt) == EFI_SUCCESS);
  assert(OppoPlanEarlyMemory(&info, image, pool, TRUE, &acpi) == EFI_SUCCESS);
  assert(acpi.ProtectedCount == 4);
  assert(dt.ProtectedType[2] == EfiBootServicesData);
  assert(acpi.ProtectedType[0] == EfiReservedMemoryType && !acpi.ProtectedWriteBack[0]);
  assert(acpi.ProtectedType[1] == EfiBootServicesData && acpi.ProtectedWriteBack[1]);
  assert(acpi.ProtectedType[2] == EfiReservedMemoryType && acpi.ProtectedWriteBack[2]);
  assert(acpi.ProtectedType[3] == EfiBootServicesCode && !acpi.ProtectedWriteBack[3]);
  assert(memcmp(dt.Protected, acpi.Protected, sizeof acpi.Protected) == 0);
  assert(memcmp(dt.ProtectedWriteBack, acpi.ProtectedWriteBack, sizeof acpi.ProtectedWriteBack) == 0);
}

static void private_capture(const char *path)
{
  FILE *f = fopen(path, "rb");
  assert(f && fseek(f, 0, SEEK_END) == 0);
  long bytes = ftell(f);
  assert(bytes >= 40 && bytes <= 2 * 1024 * 1024 && fseek(f, 0, SEEK_SET) == 0);
  UINT8 *raw = malloc((size_t)bytes);
  assert(raw && fread(raw, 1, (size_t)bytes, f) == (size_t)bytes); fclose(f);
  OPPO_BOOT_HANDOFF info;
  OPPO_EARLY_MEMORY_PLAN plan, acpi;
  // This is a supplied address for offline planning, not a measured entry x0.
  assert(OppoInspectHandoff(raw, (UINTN)bytes, 0x57300000, &info) == EFI_SUCCESS);
  assert(OppoPlanEarlyMemory(&info, (OPPO_MEMORY_RANGE){0x40080000, 0x800000},
                            (OPPO_MEMORY_RANGE){0x43000000, 0x4000000}, FALSE, &plan) == EFI_SUCCESS);
  assert(plan.DynamicReservationsDeferredToOs == 6 && plan.EmptyNodesIgnored == 1);
  printf("Offline capture-based proposal: 64 MiB pool, 8 MiB image, %zu protected ranges; no physical allocation.\n",
         (size_t)plan.ProtectedCount);
  assert(OppoPlanEarlyMemory(&info, plan.Image, plan.Pool, TRUE, &acpi) == EFI_SUCCESS);
  assert(acpi.ProtectedCount == plan.ProtectedCount);
  assert(memcmp(plan.Protected, acpi.Protected, sizeof acpi.Protected) == 0);
  assert(memcmp(plan.ProtectedWriteBack, acpi.ProtectedWriteBack, sizeof acpi.ProtectedWriteBack) == 0);
  UINTN promoted = 0;
  UINT64 reserved_bytes = 0;
  for (UINTN i = 0; i < acpi.ProtectedCount; i++) {
    if (plan.ProtectedType[i] == acpi.ProtectedType[i]) continue;
    assert(plan.ProtectedType[i] == EfiBootServicesData);
    assert(acpi.ProtectedType[i] == EfiReservedMemoryType && acpi.ProtectedWriteBack[i]);
    promoted++;
    reserved_bytes += acpi.Protected[i].Length;
  }
  assert(promoted == 2 && reserved_bytes == 0x81000);
  printf("Offline ACPI policy: %zu additional reserved ranges (%llu bytes); SEC mapping decisions unchanged.\n",
         (size_t)promoted, (unsigned long long)reserved_bytes);
  OPPO_ADDITIONAL_MEMORY_PLAN extra;
  assert(OppoPlanAdditionalMemory(&info,plan.Image,plan.Pool,
    (OPPO_MEMORY_RANGE){0x80000000,0x80000000},&extra)==EFI_SUCCESS);
  assert(extra.Count==4 && extra.TotalBytes==0x7ff3f000);
  for(UINTN i=0;i<extra.Count;i++) {
    assert(OppoLoadRegionIsUsable(TRUE,extra.Free[i].Base,extra.Free[i].Length,
      info.Ram,info.RamCount,plan.Protected,plan.ProtectedCount));
    printf("Offline additional slice: %llx + %llx\n",
      (unsigned long long)extra.Free[i].Base,(unsigned long long)extra.Free[i].Length);
  }
  free(raw);
}

static void additional(void)
{
  OPPO_BOOT_HANDOFF info=fixture(),changed;
  OPPO_MEMORY_RANGE image={0x40080000,0x800000},pool={0x43000000,0x4000000};
  OPPO_MEMORY_RANGE window={0x80000000,0x80000000};
  OPPO_ADDITIONAL_MEMORY_PLAN extra,before;
  assert(OppoPlanAdditionalMemory(&info,image,pool,window,&extra)==EFI_SUCCESS);
  assert(extra.Count==1 && extra.TotalBytes==window.Length && extra.Free[0].Base==window.Base);
  before=extra;
  for(UINTN test=0;test<13;test++) {
    changed=info;OPPO_MEMORY_RANGE bad=window;
    if(test==0)bad.Base++;
    if(test==1)bad.Length=4096;
    if(test==2)bad.Length=0x80001000;
    if(test==3)bad.Base=MAX_UINT64-4095;
    if(test==4)bad.Base=0x200000000;
    if(test==5)bad=pool;
    if(test==6)bad=(OPPO_MEMORY_RANGE){0x40000000,0x1000000};
    if(test==7)changed.UnresolvedReservationCount=1;
    if(test==8)changed.FdtPhysicalAddressRecorded=FALSE;
    if(test==9) {changed.Ram[1]=changed.Ram[0];changed.RamCount=2;}
    if(test==10) {changed.Ram[1]=(OPPO_MEMORY_RANGE){MAX_UINT64-4095,8192};changed.RamCount=2;}
    if(test==11)changed.ReservedFlags[0]=0x80000000;
    if(test==12) {changed.Reserved[2]=window;changed.ReservedCount=3;}
    assert(OppoPlanAdditionalMemory(&changed,image,pool,bad,&extra)!=EFI_SUCCESS);
    assert(!memcmp(&extra,&before,sizeof extra));
  }
  assert(OppoPlanAdditionalMemory(NULL,image,pool,window,&extra)==EFI_INVALID_PARAMETER);
  assert(OppoPlanAdditionalMemory(&info,image,pool,window,NULL)==EFI_INVALID_PARAMETER);
  // Differential coverage oracle: mark a page bitmap independently of the
  // interval algorithm, with shuffled, unaligned reservations and boundary clips.
  window.Length=64*1024*1024;
  const UINTN pages=window.Length/4096;
  UINT8 *expected=malloc(pages),*seen=malloc(pages);assert(expected && seen);
  for(UINTN seed=0;seed<32;seed++) {
    changed=info;memset(expected,1,pages);memset(seen,0,pages);
    for(UINTN j=0;j<32;j++) {
      UINTN slot=(j*13+seed*7)%32;
      UINT64 base=window.Base+slot*0x200000+123;
      UINT64 length=(j%3+1)*4096+99;
      changed.Reserved[j+2]=(OPPO_MEMORY_RANGE){base,length};
      changed.ReservedFlags[j+2]=j%2 ? OPPO_RESERVATION_NO_MAP : OPPO_RESERVATION_BOOT_DATA;
      for(UINTN p=0;p<pages;p++) {
        UINT64 start=window.Base+p*4096;
        if(start<base+length && base<start+4096)expected[p]=0;
      }
    }
    changed.ReservedCount=34;
    assert(OppoPlanAdditionalMemory(&changed,image,pool,window,&extra)==EFI_SUCCESS);
    UINT64 sum=0;
    for(UINTN j=0;j<extra.Count;j++) {
      OPPO_MEMORY_RANGE r=extra.Free[j];sum+=r.Length;
      assert(!(r.Base%4096) && !(r.Length%4096) && r.Length);
      assert(r.Base>=window.Base && r.Base+r.Length<=window.Base+window.Length);
      if(j)assert(extra.Free[j-1].Base+extra.Free[j-1].Length<=r.Base);
      for(UINTN p=(r.Base-window.Base)/4096;p<(r.Base+r.Length-window.Base)/4096;p++) {
        assert(!seen[p]);seen[p]=1;
      }
    }
    assert(sum==extra.TotalBytes && !memcmp(seen,expected,pages));
  }
  free(expected);free(seen);
  // Reservation clipping at both edges and raw byte adjacency are page based.
  changed=info;
  changed.Reserved[2]=(OPPO_MEMORY_RANGE){window.Base-1,2};changed.ReservedFlags[2]=1;
  changed.Reserved[3]=(OPPO_MEMORY_RANGE){window.Base+window.Length-1,2};changed.ReservedFlags[3]=1;
  changed.ReservedCount=4;
  assert(OppoPlanAdditionalMemory(&changed,image,pool,window,&extra)==EFI_SUCCESS);
  assert(extra.Count==1 && extra.Free[0].Base==window.Base+4096 && extra.TotalBytes==window.Length-8192);
  puts("Additional memory: 13 unchanged-output failures, nulls, 32 differential page-coverage cases, shuffled exclusions and boundary rounding passed; no physical RAM access.");
}

int main(int argc, char **argv)
{
  assert(argc == 1 || argc == 2);
  synthetic();
  acpi_reservation_ownership();
  additional();
  if (argc == 2) private_capture(argv[1]);
  puts("Early memory policy, page rounding, exclusions, deferred dynamic requests and unchanged failure output passed with host sanitizers.");
  return 0;
}
