/* Packet 15B descriptor-pinned worker. Fixed FDs; no argv or environment authority. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/close_range.h>
#include <linux/mount.h>
#include <linux/prctl.h>
#include <linux/securebits.h>
#include <linux/stat.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define READY 3
#define CONTINUE 4
#define PLAN 5
#define STREAM 6
#define LOG 7
#define SOURCE_BASE 10
#define RUNTIME 74
#define STAGING_BASE "/run/astral-project/staging/"
#define STAGING_MAX 128
static char staging[STAGING_MAX];
#define RUNTIME_TARGET "/.astral-project-runtime"
#define APPARMOR_EXEC "/proc/thread-self/attr/exec"
#define APPARMOR_PROFILE "aspr-sftp-v1"
#define HEADER 16
#define ENTRY 34
#define MAX_ENTRIES 64
#define MAX_TARGET 4096
static void die(const char *s) { perror(s); _exit(111); }
static void bad(const char *s) { fputs(s, stderr); fputc('\n', stderr); _exit(112); }
static uint16_t u16(const unsigned char *p) { return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static uint32_t u32(const unsigned char *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t u64(const unsigned char *p) { uint64_t v=0; unsigned int i; for(i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v; }
static int overlap_target(const unsigned char *p,size_t n,const char *reserved) {
 size_t r=strlen(reserved); return (n==r&&!memcmp(p,reserved,n)) || (n>r&&!memcmp(p,reserved,r)&&p[r]=='/') || (n<r&&!memcmp(p,reserved,n)&&reserved[n]=='/');
}
static void require_fd(int fd) { int flags=fcntl(fd,F_GETFD); if(flags<0) die("fixed descriptor unavailable"); if(flags&FD_CLOEXEC) bad("fixed descriptor has unexpected close-on-exec"); }
static void sync_map(void) { char c; if (write(READY,"R",1)!=1) die("map ready"); if(read(CONTINUE,&c,1)!=1||c!='C') bad("mapping continuation invalid"); }
static void verify_fd(int fd,uint64_t dev,uint64_t ino,uint64_t mnt,unsigned char kind) {
 struct statx st; unsigned int type=kind==1?S_IFREG:kind==2?S_IFDIR:0;
 if(!type) bad("plan kind invalid");
 if(syscall(SYS_statx,fd,"",AT_EMPTY_PATH,STATX_BASIC_STATS|STATX_MNT_ID,&st)) die("statx");
 if(!(st.stx_mask&STATX_MNT_ID)||makedev(st.stx_dev_major,st.stx_dev_minor)!=dev||st.stx_ino!=ino||st.stx_mnt_id!=mnt||(st.stx_mode&S_IFMT)!=type) bad("source descriptor identity mismatch");
}
static void valid_target(const unsigned char *p,size_t n) {
 size_t start=1,i; if(n<2||p[0]!='/') bad("target invalid");
 if(overlap_target(p,n,RUNTIME_TARGET)||overlap_target(p,n,"/oldroot")||overlap_target(p,n,"/.astral-project")) bad("target overlaps reserved path");
 for(i=1;i<=n;i++) if(i==n||p[i]=='/') { size_t l=i-start; if(!l||(l==1&&p[start]=='.')||(l==2&&p[start]=='.'&&p[start+1]=='.')) bad("target invalid"); start=i+1; } else if(!p[i]) bad("target invalid");
}
static void make_target(char *p,unsigned char kind) {
 char *q=p+strlen(staging); for(;*q;q++) if(*q=='/') { *q=0; if(mkdir(p,0700)&&errno!=EEXIST) die("mkdir"); *q='/'; }
 if(kind==2) { if(mkdir(p,0700)&&errno!=EEXIST) die("mkdir target"); }
 else { int fd=open(p,O_CREAT|O_EXCL|O_CLOEXEC,0600); if(fd<0&&errno!=EEXIST) die("create target"); if(fd>=0) close(fd); }
}
static void mount_one(int source,char *target,unsigned char access,unsigned char noexec) {
 int tree=syscall(SYS_open_tree,source,"",OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH);
 struct mount_attr a={.attr_set=MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV};
 if(tree<0) die("open_tree");
 if(access==1) a.attr_set|=MOUNT_ATTR_RDONLY;
 else if(access!=2) bad("access invalid");
 if(noexec) a.attr_set|=MOUNT_ATTR_NOEXEC;
 if(syscall(SYS_mount_setattr,tree,"",AT_EMPTY_PATH,&a,sizeof(a))) die("mount_setattr");
 if(syscall(SYS_move_mount,tree,"",AT_FDCWD,target,MOVE_MOUNT_F_EMPTY_PATH)) die("move_mount");
 close(tree);
}
static void attach_runtime(void) {
 struct stat st; char target[STAGING_MAX+sizeof(RUNTIME_TARGET)];
 if(fstat(RUNTIME,&st)||!S_ISDIR(st.st_mode)) bad("runtime descriptor invalid");
 if(snprintf(target,sizeof(target),"%s%s",staging,RUNTIME_TARGET)>=((int)sizeof(target))) bad("runtime target too long");
 make_target(target,2); mount_one(RUNTIME,target,1,0);
}
static void enter_synthetic_root(void) {
 char oldroot[STAGING_MAX+sizeof("/oldroot")];
 if(snprintf(oldroot,sizeof(oldroot),"%s/oldroot",staging)>=((int)sizeof(oldroot))) bad("oldroot target too long");
 if(mkdir(oldroot,0700)&&errno!=EEXIST) die("mkdir oldroot");
 if(chdir(staging)) die("chdir staging");
 if(syscall(SYS_pivot_root,".","oldroot")) die("pivot_root");
 if(chdir("/")) die("chdir root");
 if(umount2("/oldroot",MNT_DETACH)) die("umount oldroot");
 if(rmdir("/oldroot")) die("rmdir oldroot");
}
static void arm_apparmor_transition(void) {
 const char transition[]="exec " APPARMOR_PROFILE; int fd=open(APPARMOR_EXEC,O_WRONLY|O_CLOEXEC);
 if(fd<0) die("open AppArmor exec attribute");
 if(write(fd,transition,sizeof(transition)-1)!=(ssize_t)(sizeof(transition)-1)) die("write AppArmor exec attribute");
 if(close(fd)) die("close AppArmor exec attribute");
}
static void discard_setup_authority(void) {
 struct __user_cap_header_struct header={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
 struct __user_cap_data_struct data[2]={{0}}; int cap;
 if(prctl(PR_SET_SECUREBITS,SECBIT_NOROOT|SECBIT_NOROOT_LOCKED|SECBIT_NO_SETUID_FIXUP|SECBIT_NO_SETUID_FIXUP_LOCKED|SECBIT_NO_CAP_AMBIENT_RAISE|SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,0,0)) die("securebits");
 if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)) die("clear ambient capabilities");
 for(cap=0;cap<=CAP_LAST_CAP;cap++) if(prctl(PR_CAPBSET_DROP,cap,0,0,0)) die("drop capability bounding set");
 if(syscall(SYS_capset,&header,&data)) die("capset");
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) die("no_new_privs");
}
static void run_fixed_sftp(void) {
 char *const argv[]={"/.astral-project-runtime/ld.so","--library-path","/.astral-project-runtime/lib","/.astral-project-runtime/sftp-server","-e","-l","INFO",NULL};
 char *const envp[]={"HOME=/","LANG=C","PATH=/usr/bin:/bin",NULL};
 if(dup2(STREAM,STDIN_FILENO)<0||dup2(STREAM,STDOUT_FILENO)<0||dup2(LOG,STDERR_FILENO)<0) die("dup workload channels");
 if(syscall(SYS_close_range,3,~0U,0)) die("close_range");
 execve(argv[0],argv,envp); die("exec fixed sftp");
}
int main(int argc,char **argv) {
 struct stat f; unsigned char *p,*seen; size_t n,o=HEADER; uint32_t count,i; (void)argv;
 if(argc!=1) return 64;
 if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)) die("parent death signal");
 if(getppid()==1) bad("broker parent already exited");
 if(snprintf(staging,sizeof(staging),"%s%ld",STAGING_BASE,(long)getpid())>=((int)sizeof(staging))) bad("staging path too long");
 if(unshare(CLONE_NEWUSER)) die("unshare user namespace");
 sync_map();
 { int seals=fcntl(PLAN,F_GET_SEALS); if(seals<0) die("F_GET_SEALS"); if((seals&(F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL))!=(F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL)) bad("plan unsealed"); }
 require_fd(STREAM); require_fd(LOG); require_fd(RUNTIME);
 if(fstat(PLAN,&f)||f.st_size<HEADER||f.st_size>65536) bad("plan size invalid");
 n=f.st_size; p=malloc(n); seen=calloc(MAX_ENTRIES,1);
 if(!p||!seen) die("plan allocation");
 if(pread(PLAN,p,n,0)!=(ssize_t)n) die("plan read");
 if(memcmp(p,"ASPRPLN1",8)||u32(p+8)!=1||(count=u32(p+12))==0||count>MAX_ENTRIES) bad("plan header invalid");
 /* Verify every source in broker mount namespace before CLONE_NEWNS. */
 for(i=0;i<count;i++) { uint32_t slot; unsigned char kind; uint16_t len;
  if(o+ENTRY>n) bad("plan truncated");
  slot=u32(p+o);kind=p[o+5];len=u16(p+o+32);
  if(slot>=count||seen[slot]||len>MAX_TARGET||o+ENTRY+len>n) bad("plan entry invalid");
  seen[slot]=1; valid_target(p+o+ENTRY,len);
  require_fd(SOURCE_BASE+slot); verify_fd(SOURCE_BASE+slot,u64(p+o+8),u64(p+o+16),u64(p+o+24),kind);
  o+=ENTRY+len;
 }
 if(o!=n) bad("plan trailing data");
 if(unshare(CLONE_NEWNS)) die("unshare mount namespace");
 if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)) die("private mounts");
 if(mkdir(staging,0700)&&errno!=EEXIST) die("mkdir worker staging");
 if(mount("tmpfs",staging,"tmpfs",MS_NOSUID|MS_NODEV,"mode=0700")) die("staging tmpfs");
 o=HEADER; memset(seen,0,MAX_ENTRIES);
 for(i=0;i<count;i++) { uint32_t slot; unsigned char access,kind; uint16_t len; char target[STAGING_MAX+MAX_TARGET+1];
  if(o+ENTRY>n) bad("plan truncated");
  slot=u32(p+o);access=p[o+4];kind=p[o+5];len=u16(p+o+32);
  if(slot>=count||seen[slot]||len>MAX_TARGET||o+ENTRY+len>n) bad("plan entry invalid");
  seen[slot]=1;
  if(strlen(staging)+len>=sizeof(target)) bad("target too long");
  memcpy(target,staging,strlen(staging)); memcpy(target+strlen(staging),p+o+ENTRY,len); target[strlen(staging)+len]=0;
  make_target(target,kind); mount_one(SOURCE_BASE+slot,target,access,1); o+=ENTRY+len;
 }
 if(o!=n) bad("plan trailing data");
 if(fcntl(PLAN,F_SETFD,FD_CLOEXEC)||fcntl(RUNTIME,F_SETFD,FD_CLOEXEC)) die("set setup close-on-exec");
 attach_runtime();
 arm_apparmor_transition();
 enter_synthetic_root();
 discard_setup_authority();
 run_fixed_sftp();
 return 111;
}
