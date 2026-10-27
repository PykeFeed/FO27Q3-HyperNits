/*
 * FO27Q3 F05 HyperNits (Off / Medium / High) - patch + flash launcher.   EXPERIMENTAL.
 *
 * What it does:
 *   1. Finds the OFFICIAL Gigabyte FWUPD folder (UpdFW_RTK.exe, RFlash.dll, ... F05.bin) and checks every
 *      file against known SHA-256 values.
 *   2. Applies the embedded byte patch to the official F05.bin in memory and checks the result against the
 *      expected SHA-256 of the experimental image.
 *   3. Builds a work folder next to this exe containing the official updater files plus the patched F05.bin
 *      (named F05.bin, as upd.xml expects) and keeps the untouched original in "original_backup".
 *   4. Only with --flash AND typed confirmations: starts the official updater (UpdFW_RTK.exe) from that folder.
 *      The vendor tool performs the real flash (chip erase + bank write) over the monitor's USB upstream port.
 *
 * It does NOT implement its own flasher, does NOT bypass the updater's model check, and does NOT touch the
 * monitor unless you press the update button inside the vendor tool.
 * The patched image has only been tested on one single unit. A failed or interrupted flash can leave the monitor
 * unusable; the vendor updater may not be able to rescue it (needs an external SPI programmer).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#endif
#include "patch_data.h"

/* ---------- SHA-256 ---------- */
typedef struct{uint32_t h[8];uint64_t len;uint8_t buf[64];size_t n;}sha_t;
static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha_block(sha_t*s,const uint8_t*p){uint32_t w[64],a,b,c,d,e,f,g,h,t1,t2;int i;
 for(i=0;i<16;i++)w[i]=(uint32_t)p[4*i]<<24|(uint32_t)p[4*i+1]<<16|(uint32_t)p[4*i+2]<<8|p[4*i+3];
 for(i=16;i<64;i++){uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3),s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
 a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
 for(i=0;i<64;i++){t1=h+(ROR(e,6)^ROR(e,11)^ROR(e,25))+((e&f)^(~e&g))+K[i]+w[i];t2=(ROR(a,2)^ROR(a,13)^ROR(a,22))+((a&b)^(a&c)^(b&c));h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
 s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;}
static void sha_init(sha_t*s){static const uint32_t i[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s->h,i,32);s->len=0;s->n=0;}
static void sha_upd(sha_t*s,const uint8_t*d,size_t l){s->len+=l;while(l){size_t k=64-s->n;if(k>l)k=l;memcpy(s->buf+s->n,d,k);s->n+=k;d+=k;l-=k;if(s->n==64){sha_block(s,s->buf);s->n=0;}}}
static void sha_hex(const uint8_t*d,size_t l,char out[65]){sha_t s;uint8_t pad[72]={0x80};uint64_t bits;size_t pl,i;sha_init(&s);sha_upd(&s,d,l);bits=s.len*8;pl=(s.n<56)?(56-s.n):(120-s.n);
 sha_upd(&s,pad,pl);{uint8_t b[8];for(i=0;i<8;i++)b[i]=(uint8_t)(bits>>(56-8*i));sha_upd(&s,b,8);}
 for(i=0;i<8;i++)sprintf(out+8*i,"%08x",s.h[i]);}

/* ---------- files ---------- */
static uint8_t*read_all(const char*p,size_t*len){FILE*f=fopen(p,"rb");uint8_t*b;long n;if(!f)return NULL;fseek(f,0,SEEK_END);n=ftell(f);fseek(f,0,SEEK_SET);b=(uint8_t*)malloc(n?n:1);if(!b||fread(b,1,n,f)!=(size_t)n){fclose(f);free(b);return NULL;}fclose(f);*len=n;return b;}
static int write_all(const char*p,const uint8_t*b,size_t n){FILE*f=fopen(p,"wb");int ok;if(!f)return 0;ok=fwrite(b,1,n,f)==n;ok&=fclose(f)==0;return ok;}
static int exists(const char*p){FILE*f=fopen(p,"rb");if(f){fclose(f);return 1;}return 0;}
static void mkdir_p(const char*p){
#ifdef _WIN32
 CreateDirectoryA(p,NULL);
#else
 mkdir(p,0755);
#endif
}
static void join(char*o,size_t n,const char*a,const char*b){snprintf(o,n,"%s%c%s",a,
#ifdef _WIN32
 '\\'
#else
 '/'
#endif
 ,b);}
static void exe_dir(char*o,size_t n){
#ifdef _WIN32
 DWORD k=GetModuleFileNameA(NULL,o,(DWORD)n);char*s;if(!k){strcpy(o,".");return;}s=strrchr(o,'\\');if(s)*s=0;
#else
 ssize_t k=readlink("/proc/self/exe",o,n-1);char*s;if(k<=0){strcpy(o,".");return;}o[k]=0;s=strrchr(o,'/');if(s)*s=0;
#endif
}
typedef struct{const char*name;const char*sha;}vf_t;
static const vf_t VENDOR[]={
 {"F05.bin",STOCK_SHA256},
 {"RFlash.dll","1e42f73bc1d9ddf80c1cb7e7d2c239694b1ed21edd74a4adc887de30d6aa578e"},
 {"RTKCmd_x64.dll","ee6994c6b6409cbbaa3a9268b4d289dce145c40218ee2be21fddaebeeb6e940f"},
 {"RtHIDlib.dll","c17dead83dd78334419f9a81e700a67a2fc1d74e0d705f3b99fec1f1febb6c03"},
 {"UpdFW_RTK.exe","a55052b0af62604ff95ad193851664cb20198b418b2ed0e839d3ba4e849fcaad"},
 {"upd.xml","c56b9ec25974e03404b6b4d13cf164e8028ce41b72789e2997aabcd1573bbe54"}};
#define NV (int)(sizeof(VENDOR)/sizeof(VENDOR[0]))

static int find_fwupd(const char*arg,const char*ed,char*out,size_t n){
 char c[4][1024];int i;char t[1100];
 if(arg){snprintf(out,n,"%s",arg);join(t,sizeof t,out,"UpdFW_RTK.exe");return exists(t);}
 join(c[0],1024,ed,"FWUPD");
 snprintf(c[1],1024,"%s%cextracted%cAORUS_FO27Q3_F05%cFWUPD",ed,'/','/','/');
 snprintf(c[2],1024,"%s%c..%cextracted%cAORUS_FO27Q3_F05%cFWUPD",ed,'/','/','/','/');
 snprintf(c[3],1024,"%s%c..%c..%cextracted%cAORUS_FO27Q3_F05%cFWUPD",ed,'/','/','/','/','/');
 for(i=0;i<4;i++){
#ifdef _WIN32
  char*p;for(p=c[i];*p;p++)if(*p=='/')*p='\\';
#endif
  join(t,sizeof t,c[i],"UpdFW_RTK.exe");if(exists(t)){snprintf(out,n,"%s",c[i]);return 1;}}
 return 0;}

static int ask(const char*q,const char*want){char b[256];printf("%s",q);fflush(stdout);if(!fgets(b,sizeof b,stdin))return 0;b[strcspn(b,"\r\n")]=0;return strcmp(b,want)==0;}

int main(int argc,char**argv){
 const char*fw=NULL;int flash=0,norec=0,i;char ed[1024],src[1100],work[1100],orig[1100],a[1200],b[1200],h[65];
 for(i=1;i<argc;i++){
  if(!strcmp(argv[i],"--fwupd")&&i+1<argc)fw=argv[++i];
  else if(!strcmp(argv[i],"--flash"))flash=1;
  else if(!strcmp(argv[i],"--accept-no-recovery"))norec=1;
  else{printf("FO27Q3 HyperNits (Off / Medium / High) patch/flash launcher - EXPERIMENTAL\n\nUsage: %s [--fwupd <official FWUPD folder>] [--flash] [--accept-no-recovery]\n\n  (no options)  verify official files, build the patched package, do NOT start the updater\n  --flash       after verification and typed confirmations, start the official updater from the package\n",argv[0]);return 2;}
 }
 exe_dir(ed,sizeof ed);
 if(!find_fwupd(fw,ed,src,sizeof src)){printf("ERROR: official FWUPD folder (with UpdFW_RTK.exe) not found. Use --fwupd <folder>.\n");return 1;}
 printf("Official updater folder: %s\n",src);
 /* 1. verify vendor files */
 for(i=0;i<NV;i++){size_t l;uint8_t*d;join(a,sizeof a,src,VENDOR[i].name);d=read_all(a,&l);
  if(!d){printf("ERROR: cannot read %s\n",a);return 1;}
  sha_hex(d,l,h);free(d);
  if(strcmp(h,VENDOR[i].sha)){printf("ERROR: %s hash mismatch\n  expected %s\n  actual   %s\nRefusing: this is not the official F05 updater package.\n",VENDOR[i].name,VENDOR[i].sha,h);return 1;}
  printf("  ok  %-16s %s\n",VENDOR[i].name,h);}
 /* 2. patch in memory */
 {size_t l;uint8_t*img;join(a,sizeof a,src,"F05.bin");img=read_all(a,&l);if(!img||l!=IMAGE_SIZE){printf("ERROR: unexpected F05.bin size\n");return 1;}
  for(i=0;i<RUN_COUNT;i++){if(RUNS[i].off+RUNS[i].len>l){printf("ERROR: patch out of range\n");return 1;}memcpy(img+RUNS[i].off,RUNS[i].data,RUNS[i].len);}
  sha_hex(img,l,h);
  if(strcmp(h,PATCHED_SHA256)){printf("ERROR: patched image hash mismatch\n  expected %s\n  actual   %s\n",PATCHED_SHA256,h);return 1;}
  printf("Patched image OK: %zu bytes, SHA-256 %s (%d patch regions)\n",l,h,RUN_COUNT);
  /* 3. build package */
  join(work,sizeof work,ed,"FO27Q3_HyperNits_flash_package");mkdir_p(work);
  join(orig,sizeof orig,work,"original_backup");mkdir_p(orig);
  for(i=0;i<NV;i++){size_t k;uint8_t*d;join(a,sizeof a,src,VENDOR[i].name);d=read_all(a,&k);
   if(i==0){join(b,sizeof b,orig,"F05.bin");if(!write_all(b,d,k)){printf("ERROR: write failed\n");return 1;}
            join(b,sizeof b,work,"F05.bin");if(!write_all(b,img,l)){printf("ERROR: write failed\n");return 1;}}
   else{join(b,sizeof b,work,VENDOR[i].name);if(!write_all(b,d,k)){printf("ERROR: write failed\n");return 1;}}
   free(d);}
  free(img);}
 printf("Package ready: %s\n  (patched F05.bin + official updater files; untouched original in original_backup\\)\n",work);
 if(!flash){printf("\nDry run finished. Nothing was flashed and the updater was not started.\nRe-run with --flash to start the official updater.\n");return 0;}
 /* 4. confirmations */
 printf("\n==================== WARNING ====================\n"
  "This firmware has only been tested on ONE single monitor. Flashing modified firmware voids your monitor's warranty. You flash at your own risk; the author is not responsible for a bricked monitor. The updater does a full chip erase then rewrites flash.\n"
  "If anything goes wrong (bad image, USB or power loss) the scaler can be left blank. The stock updater may\n"
  "NOT be able to recover it; recovery needs an external SPI programmer + a verified backup of the chip.\n"
  "Use a stable power source, keep the monitor's USB UPSTREAM cable connected, close other updaters.\n"
  "=================================================\n\n");
 if(!norec){if(!ask("Do you have a verified external SPI flash backup AND a way to restore it? Type YES to continue: ","YES")){printf("Aborted. (Use --accept-no-recovery only if you accept a possible permanent brick.)\n");return 3;}}
 else printf("--accept-no-recovery given: proceeding WITHOUT a recovery path.\n");
 if(!ask("Type exactly  FLASH MY FO27Q3  to start the official updater: ","FLASH MY FO27Q3")){printf("Aborted.\n");return 3;}
 join(a,sizeof a,work,"UpdFW_RTK.exe");
#ifdef _WIN32
 {STARTUPINFOA si;PROCESS_INFORMATION pi;DWORD ec=0;char cmd[1300];memset(&si,0,sizeof si);si.cb=sizeof si;snprintf(cmd,sizeof cmd,"\"%s\"",a);
  if(!CreateProcessA(a,cmd,NULL,NULL,FALSE,0,NULL,work,&si,&pi)){printf("ERROR: could not start updater (%lu)\n",GetLastError());return 1;}
  printf("Official updater started. Use its update button; do not unplug or power off until it reports success.\n");
  WaitForSingleObject(pi.hProcess,INFINITE);GetExitCodeProcess(pi.hProcess,&ec);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);printf("Updater exited with code %lu\n",ec);return (int)ec;}
#else
 printf("(non-Windows test build: would start %s)\n",a);return 0;
#endif
}
