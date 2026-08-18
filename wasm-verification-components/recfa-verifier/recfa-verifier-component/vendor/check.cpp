/* Vendored from upstream ReCFA (ACSAC'21) src/verifier/check.cpp
 *   https://github.com/suncongxd/ReCFA
 *   upstream sha256: 9f72861d5f860ecaf574eca63c038e93b163cd20fb6df93e11b4da1740c8beef
 *
 * DO NOT EDIT BY HAND. Regenerate with:
 *   python3 patch-upstream.py /path/to/ReCFA/src/verifier/check.cpp
 *
 * Every deviation from upstream carries a RECFA-PORT marker comment.
 */
#include <algorithm>
#include <bitset>
#include <cstdint>
#include <map>
#include <stack>
#include <fstream>
#include <iostream>
#include <queue>
#include <regex>
#include <set>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <time.h>
using namespace std;

/* ==== RECFA-PORT: additive support code, no upstream logic changed ======== */
#include "recfa_entry.h"
#include <cstddef>
#include <cstring>

/* Inputs are handed to us as memory buffers by the Wasm component shell, keyed
   by the same "filenames" that are passed down as argv. This lets every upstream
   parser keep its `char *file` signature and its exact parsing code, while the
   component needs no filesystem access at all. */
static std::map<std::string, std::string> g_vfs;

static int g_fatal = 0;                 /* RECFA_VERDICT_* once a fatal path hit */
static int g_verdict = RECFA_VERDICT_UNKNOWN;
static long long g_unprocessed = 0;     /* sto->size() at a shadow-stack failure */
static unsigned int g_last_site = 0;    /* transfer instruction being checked     */
static unsigned int g_bad_target = 0;   /* the target that violated the policy    */
static unsigned int g_main_addr = 0, g_ret_addr = 0;

extern "C" void recfa_vfs_put(const char *name, const unsigned char *data,
                              unsigned long len) {
  g_vfs[std::string(name)] = std::string((const char *)data, (size_t)len);
}
extern "C" void recfa_vfs_clear(void) { g_vfs.clear(); }

/* Drop-in replacement for `fstream f(path)`: a non-copying istream over the VFS
   entry, so a 100 MB .asm is not duplicated in linear memory. */
struct RecfaIn : std::istream {
  struct Buf : std::streambuf {
    Buf(const char *p, size_t n) {
      setg(const_cast<char *>(p), const_cast<char *>(p), const_cast<char *>(p) + n);
    }
  };
  Buf buf_;
  explicit RecfaIn(const char *name)
      : std::istream(NULL),
        buf_(g_vfs.count(name) ? g_vfs[name].data() : "",
             g_vfs.count(name) ? g_vfs[name].size() : 0) {
    this->rdbuf(&buf_);
  }
};

/* Drop-in replacement for `fopen(path, "r")` on the event stream. */
static FILE *recfa_fopen(const char *name) {
  std::map<std::string, std::string>::iterator it = g_vfs.find(name);
  if (it == g_vfs.end())
    return NULL;
  return fmemopen(const_cast<char *>(it->second.data()), it->second.size(), "rb");
}

/* Owning stand-in for upstream's `char *c`. Upstream does
     c = (char *)(m.str(1)).c_str();
     b = strtoll(c, NULL, 16);
   where the std::string temporary dies at the end of the first statement, so the
   second reads freed memory. Assigning through this holder copies the bytes while
   the temporary is still alive; every use site stays character-for-character the
   same because of the implicit conversion back to char *. */
struct RecfaStr {
  std::string s;
  RecfaStr() {}
  RecfaStr(const char *p) { s = (p ? p : ""); }
  RecfaStr &operator=(const char *p) {
    s = (p ? p : "");
    return *this;
  }
  operator char *() { return const_cast<char *>(s.c_str()); }
};
/* ======================================================================== */
class newblock {
public:
  int Type; //间接调用是1，间接跳转是2，直接跳转是3
  int Pair;
  int next;
  int directTarget;
  set<int> Jump;
};
map<int, newblock> proMap;
map<int, int> ForNext;

/* RECFA-PORT
   Upstream writes `proMap.find(buffer)->second.directTarget` with no check that
   the lookup succeeded, dereferencing end() when it fails. That is not merely an
   adversarial edge case: it happens on every well-formed trace. Once `executetime`
   runs have been consumed, the trailing 0xffffeeee run marker falls through to the
   compressed-direct-call branch, and stripping its high bit yields 0x7fffeeee --
   the end-of-program sentinel, which is deliberately not a call site. verifi()
   relies on that sentinel to terminate successfully, so this lookup has to fail
   benignly rather than be rejected. Returning a defined 0 preserves upstream's
   control flow exactly while removing the indeterminate read; the pushed target is
   never examined, because verifi() stops at the sentinel ahead of it. */
static int recfa_direct_target(int site) {
  map<int, newblock>::iterator it = proMap.find(site);
  return (it == proMap.end()) ? 0 : it->second.directTarget;
}
void readAsmFile(char *file, set<int> *IndirectSet, int *Main,
                 set<int> *IndirectCall, int *Ret, string compiler_type);
void readDyninst(char *file, set<int> *IndirectSet);
void readTypeAmror(char *file, set<int> *IndirectSet);
void readForToNext(char *file);
void readReceive(char *file, int Main, int Ret);
void FtoN(queue<int> *sto, int For);
void verifiSecond(queue<int> *sto, FILE *in, int Ret, int Main);
bool verifi(queue<int> *sto, FILE *in, stack<int> *shadow, int Ret, int Main);
long success = 0, total = 0;
double timeRead = 0, timeTotal = 0;
int executetime = 0;

static int recfa_check_main(int argc, char *argv[]) {   /* RECFA-PORT */
  if (argc != 8) {
    printf("Usage: ./check [disassem_file_path] [dyninst_graph_path] "
           "[policy_F_path] [policy_M_path] [folded_runtime_event_path] "
           "[num_executions] [compiler_type(gcc/llvm)].\n");
    return -1;   /* RECFA-PORT */
  }
  char *file;
  int Main = 0;
  int Ret = 0;
  set<int> *IndirectSet, *IndirectCall;
  set<int> a, b;
  IndirectSet = &a;
  IndirectCall = &b;
  // string
  // str="/home/ly/workspace/indirectjump/sourcecode/test/zuoye/AmyZhang319-resilientremoteattestation-2a9089600d1b/llvm-10/O1/gcc.cfa_huibian.txt";
  // //读汇编文件pair对和和call，顺便读取间接调用的集合,同事获取main函数 string
  // str="/root/liu/check/llvmO0/O0/gcc_base.huibian.txt";
  // string str = "";
  // printf("输入反汇编文件\n");
  // getline(cin, str);
  // string str="/root/liu/check/O0gcc/O0/gcc_base.cfa_huibian.txt";
  // file = (char *)str.c_str();
  readAsmFile(argv[1], IndirectSet, &Main, IndirectCall, &Ret, argv[7]);
  g_main_addr = (unsigned int)Main;   /* RECFA-PORT */
  g_ret_addr = (unsigned int)Ret;
  // printf("main%xret%x",Main,Ret);
  // printf("输入Dyninst分析文件\n");
  // getline(cin, str);
  // str="/root/liu/check/O0gcc/O0/gcc_base.cfa.dot";
  // file = (char *)str.c_str();
  readDyninst(argv[2], IndirectSet); //读取间接跳转
  // str="/root/liu/check/outllvm/binfo.gcc_base.llvm_O0";    //读取间接调用
  // str="/root/liu/check/outgcc/binfo.gcc_base.cfa";
  // printf("输入TypeArmor分析文件\n");
  // getline(cin, str);
  // file = (char *)str.c_str();
  readTypeAmror(argv[3], IndirectCall);
  if (g_fatal)   /* RECFA-PORT */
    return -1;
  // str="/root/liu/check/llvmO0/O0/map/gcc.txt";
  // str="/root/liu/check/O0gcc/O0/map/gcc.txt";
  // printf("输入省略点映射文件\n");
  // getline(cin, str);
  // file = (char *)str.c_str();
  readForToNext(argv[4]);
  printf("|M|= %lu, |F|= %lu\n", ForNext.size(), proMap.size());
  // exit(1);
  // str="/home/ly/workspace/上下文敏感/1_30刘测试结果/ZYMhaveDC测试结果(4_16)/liu测试结果(4_18)/gcc.cfa_O0
  // str="/root/liu/check/llvm-verifi/gcc_base.llvm_O0_liu-re_allPress";
  // str="/root/liu/check/gcc-verifi/gcc_base.cfa_O0_liu-re_allPress";
  // str="/home/ly/software/codeblock/check/gcc.cfa_liu-re";
  // printf("输入待验证文件\n");
  // getline(cin, str);
  // file = (char *)str.c_str();
  // auto iter=proMap.find(4227523)->second.Jump.begin();
  // printf("%x\n",*iter);
  // clock_t start = clock();
  // printf("输入二进制执行次数\n");
  executetime = atoi(argv[6]);
  // scanf("%d", &executetime);
  readReceive(argv[5], Main, Ret);
  // clock_t end1 = clock();
  cout << (timeTotal - timeRead) / CLOCKS_PER_SEC << endl;
  cout << "execution time (T_vrf): " << timeTotal / CLOCKS_PER_SEC << endl;
  cout << "Num of addresses attested: " << total << endl;
  return 0;   /* RECFA-PORT */
}
int st = 0;
void readAsmFile(char *file, set<int> *IndirectSet, int *Main,
                 set<int> *IndirectCall, int *Ret, string binarytype) {
  RecfaIn f(file);   /* RECFA-PORT */
  string line;
  bool flag = false;
  regex call("([0-9a-z]{6})(.*)(callq)");
  regex next("([0-9a-z]{6}):");
  regex directcall("([0-9a-z]{6})(.*)(callq)(\\s{2})([0-9a-z]{6})");
  smatch m;
  while (getline(f, line)) {
    auto ret = regex_search(line, m, call);
    while (ret) {
      newblock a;
      a.Type = 3;
      RecfaStr c;   /* RECFA-PORT */
      c = (char *)(m.str(1)).c_str();
      int b = strtoll(c, NULL, 16);
      ret = regex_search(line, m, directcall);
      if (ret) {
        int d;
        c = (char *)(m.str(5)).c_str();
        d = strtoll(c, NULL, 16);
        a.directTarget = d;
      }
      getline(f, line);
      ret = regex_search(line, m, next);
      if (ret) {
        int d;
        c = (char *)(m.str(1)).c_str();
        d = strtoll(c, NULL, 16);
        a.Pair = d;
        proMap.insert(pair<int, newblock>(b, a));
      } else {
        // cout << "失败" << endl;
        proMap.insert(pair<int, newblock>(b, a));
      }
      ret = regex_search(line, m, call);
    }
  }
  RecfaIn f1(file);   /* RECFA-PORT */
  // printf("输入文件执行类型,llvm或者gcc\n");
  // string binarytype = "";
  // getline(cin, binarytype);
  regex Indirect("([0-9a-z]{6})(.*)(jmpq   \\*%rax)");
  if (binarytype == "gcc")
    Indirect = "([0-9a-z]{6})(.*)(jmpq   \\*%rax)";
  else
    Indirect = "([0-9a-z]{6})(.*)(jmpq   \\*%rcx)";
  regex main("([0-9a-z]{6}) \\<main\\>:");
  regex main_ret("([0-9a-z]{6}):(.*)retq");
  regex IC("([0-9a-z]{6})(.*)(callq  \\*)");
  regex stat("([0-9a-z]{6}) <__stat>:");
  while (getline(f1, line)) {
    auto ret = regex_search(line, m, main);
    if (ret) {
      RecfaStr c;   /* RECFA-PORT */
      int b;
      c = (char *)(m.str(1)).c_str();
      b = strtoll(c, NULL, 16);
      (*Main) = b;
      flag = true;
      continue;
    }
    ret = regex_search(line, m, Indirect);
    if (ret) {
      RecfaStr c;   /* RECFA-PORT */
      int b;
      c = (char *)(m.str(1)).c_str();
      b = strtoll(c, NULL, 16);
      (*IndirectSet).insert(b);
    }
    ret = regex_search(line, m, IC);
    if (ret) {
      RecfaStr c;   /* RECFA-PORT */
      int b;
      c = (char *)(m.str(1)).c_str();
      b = strtoll(c, NULL, 16);
      // printf("%xcall\n",b);
      (*IndirectCall).insert(b);
    }
    ret = regex_search(line, m, main_ret);
    if (ret && flag) {
      RecfaStr c;   /* RECFA-PORT */
      int b;
      c = (char *)(m.str(1)).c_str();
      b = strtoll(c, NULL, 16);
      (*Ret) = b;
      flag = false;
    }
    ret = regex_search(line, m, stat);
    if (ret) {
      RecfaStr c;   /* RECFA-PORT */
      int b;
      c = (char *)(m.str(1)).c_str();
      b = strtoll(c, NULL, 16);
      st = b;
      /// printf("%x state", st);
    }
  }
}

void readDyninst(char *file, set<int> *IndirectSet) {
  RecfaIn f(file);   /* RECFA-PORT */
  regex block("\\[([0-9a-z]{6}),([0-9a-z]{6})");
  regex Jump("\"([0-9a-z]{6})\" -\\> \"([0-9a-z]{6})\"");
  regex Call("\"([0-9a-z]{6})\" -\\> \"([0-9a-z]{6})\" \\[color=blue");
  map<int, int> Block;
  smatch m;
  string line;
  while (getline(f, line)) {
    auto ret = regex_search(line, m, block);
    if (ret) {
      RecfaStr c = (char *)m.str(1).c_str();   /* RECFA-PORT */
      int b = strtoll(c, NULL, 16);
      c = (char *)m.str(2).c_str();
      int d = strtoll(c, NULL, 16);
      Block.insert(pair<int, int>(b, d));
      continue;
    }
    ret = regex_search(line, m, Jump);
    if (ret) {
      RecfaStr c = (char *)m.str(1).c_str();   /* RECFA-PORT */
      int b = strtoll(c, NULL, 16);
      if (!Block.count(b))
        continue;
      b = Block.find(b)->second;
      if (proMap.find(b) != proMap.end()) {
        int d;
        c = (char *)m.str(2).c_str();
        d = strtoll(c, NULL, 16);
        set<int> &set1 = (proMap.find(b)->second).Jump;
        if ((*IndirectSet).count(b)) {
          set1.insert(d);
          continue;
        }
        // cout<<m.str(2)<<"  "<<proMap.find(b)->second.Type<<endl;
        ret = regex_search(line, m, Call);
        if (ret) {
          // printf("%xjump%x\n",b,d);
          set1.insert(d);
        }
      } else {
        if ((*IndirectSet).count(b)) {
          int d;
          c = (char *)m.str(2).c_str();
          d = strtoll(c, NULL, 16);
          newblock a;
          a.Type = 2;
          a.Jump.insert(d);
          proMap.insert(pair<int, newblock>(b, a));
        }
      }
    }
  }
}

void readForToNext(char *file) {
  RecfaIn f(file);   /* RECFA-PORT */
  string line;
  regex Jump("([0-9a-z]{6}) \\[([0-9a-z]{6})");
  RecfaStr c;   /* RECFA-PORT */
  int a, b;
  smatch m;
  while (getline(f, line)) {
    auto ret = regex_search(line, m, Jump);
    if (ret) {
      c = (char *)m.str(1).c_str();
      a = strtoll(c, NULL, 16);
      c = (char *)m.str(2).c_str();
      b = strtoll(c, NULL, 16);
      // cout<<m.str(1)<<" "<<m.str(2)<<endl;
      ForNext.insert(pair<int, int>(a, b));
    }
  }
}

int count1 = 0;
int Maintotal = 1;
void readReceive(char *file, int Main, int Ret) {

  FILE *in;
  in = recfa_fopen(file);   /* RECFA-PORT */
  int buffer;
  int rbyte = 0;
  queue<int> sto;
  stack<int> shadow;
  FtoN(&sto, Main);
  // cout << sto.size() << "push" << endl;
  // printf("%dexecutetime\n", executetime);
  clock_t start, end;
  bool veri;
  while (rbyte = fread(&buffer, 4, 1, in) == 1) {
    // if((buffer&16777216)&&Maintotal<executetime)
    if (buffer == 0xffffeeee && Maintotal < executetime) {
      Maintotal++;
      // printf("%xssssssssssssssssssss",buffer);
      count1 = 0;
      FtoN(&sto, Main);
      fread(&buffer, 4, 1, in);
    }
    // printf("%x\n",buffer);
    if (buffer & (2147483648)) {
      // printf("%xbefore\n",buffer);
      buffer = buffer - 2147483648;
      // printf("%xafter\n",buffer);
      sto.push(buffer);
      sto.push(recfa_direct_target(buffer));   /* RECFA-PORT */
      // printf("%xhhhhhhhhhhh\n",proMap.find(buffer)->second.directTarget);
      buffer = recfa_direct_target(buffer);   /* RECFA-PORT */
      count1 = count1 ^ 1;
    } else
      sto.push(buffer);
    if ((count1 = (count1 ^ 1)) == 0) {
      FtoN(&sto, buffer);
    }
    // if(sto.size()>1869)
    // exit(-1);
    if (sto.size() > 10000000 && (sto.size() % 2 == 0)) {
      start = clock();
      bool out = verifi(&sto, in, &shadow, Ret, Main);
      end = clock();
      timeTotal = timeTotal + (end - start);
      if (out) {
        fclose(in);
        return;
      }
    }
  }
  /// printf("gcc");
  start = clock();
  veri = verifi(&sto, in, &shadow, Ret, Main);
  end = clock();
  timeTotal = timeTotal + (end - start);
  if (!veri) {
    cout << total << "events sucess" << endl;
    cout << "No events left unprocessed.Progarm is secure" << endl;
    g_verdict = RECFA_VERDICT_SECURE;   /* RECFA-PORT */
  }
  fclose(in);
}
void FtoN(queue<int> *sto, int For) {
  if (g_fatal)   /* RECFA-PORT */
    return;
  if (ForNext.count(For)) {
    int b = ForNext.find(For)->second;
    if (proMap.find(b) == proMap.end()) {   /* RECFA-PORT */
      g_fatal = RECFA_VERDICT_DYNINST;
      return;
    }
    // sto->push(b);
    if (proMap.find(b)->second.Jump.size() != 1) {
      cout << "dyninst fail  " << proMap.find(b)->second.Jump.size() << endl;
      g_fatal = RECFA_VERDICT_DYNINST;   /* RECFA-PORT */
      return;
    }
    auto iter = proMap.find(b)->second.Jump.begin();
    int c = *iter;
    if (c == st) {
      // printf("%x %xprestat ",sto->front(),c);
      return;
    }
    // printf("%xinsert\n",b);
    // printf("%xinsert\n",c);
    sto->push(b);
    sto->push(c);
    // if(b==0x69ec90)
    // printf("Pre%x\n",For);
    // printf("Next%x\n",b);
    // cout<<"success"<<endl;
    success++;
    FtoN(sto, c);
  }
}

bool verifi(queue<int> *sto, FILE *in, stack<int> *shadow, int Ret, int Main) {
  int buffer;
  bool flag = false;
  clock_t start, end;
  while (!sto->empty()) {
    if (g_fatal)   /* RECFA-PORT */
      return true;
    buffer = sto->front();
    sto->pop();
    total++;
    // if(total>800000)
    //{
    // printf("%x\n",buffer);
    // printf("%x\n",sto->front());
    //}
    // if(total>817200)
    // exit(-1);
    if (proMap.count(buffer)) {
      g_last_site = (unsigned int)buffer;   /* RECFA-PORT */
      newblock block = proMap.find(buffer)->second;
      int type = block.Type;
      if (type == 1) {
        shadow->push(block.Pair);
        // cout<<"Indirect Call"<<endl;
        if (sto->empty()) {
          start = clock();
          verifiSecond(sto, in, Ret, Main);
          end = clock();
          timeRead = timeRead + (end - start);
        }
        buffer = sto->front();
        sto->pop();
        total++;
        if (block.Jump.count(buffer))
          continue;
        else {
          cout << "Indirect Call" << endl;
          g_fatal = RECFA_VERDICT_ICALL;   /* RECFA-PORT */
          g_bad_target = (unsigned int)buffer;
          return true;
        }
      }
      if (type == 2) {
        if (sto->empty()) {
          start = clock();
          verifiSecond(sto, in, Ret, Main);
          end = clock();
          timeRead = timeRead + (end - start);
        }
        buffer = sto->front();
        sto->pop();
        total++;
        if (block.Jump.count(buffer))
          continue;
        else {
          cout << "Indirect Jump" << endl;
          g_fatal = RECFA_VERDICT_IJMP;   /* RECFA-PORT */
          g_bad_target = (unsigned int)buffer;
          return true;
        }
      }
      if (type == 3) {
        if (sto->empty()) {
          start = clock();
          verifiSecond(sto, in, Ret, Main);
          end = clock();
          timeRead = timeRead + (end - start);
        }
        sto->pop();
        total++;
        shadow->push(block.Pair);
        // printf("shadow%x\n",block.Pair);
        continue;
      }
    } else {
      if (sto->empty()) {
        start = clock();
        verifiSecond(sto, in, Ret, Main);
        end = clock();
        timeRead = timeRead + (end - start);
      }
      if (shadow->empty()) {
        // cout<<sto->front()<<" "<<buffer<<endl;
        // printf("运行结束时栈大小%lu \n", sto->size());
        // printf("栈顶%x  当前验证地址%x ", sto->front(), buffer);
        // cout<<buffer<<"  "<<Ret<<endl;
        // printf("Stack top:%x  Ret target:%x\n", buffer, Ret);
        if (buffer == Ret && (sto->front() == (0x7fffeeee))) {
          // printf("%x ", sto->front());
          // cout << "成功" << endl << total << endl;
          cout << total << "events sucess" << endl;
          cout << "No events left unprocessed.Progarm is secure" << endl;
          g_verdict = RECFA_VERDICT_SECURE;   /* RECFA-PORT */
          return true;
        } else
          continue;
      }
      if (sto->front() == shadow->top()) {
        // cout<<sto->front()<<"  "<<shadow->top()<<endl;
        sto->pop();
        total++;
        shadow->pop();
      } else
      // cout<<sto->front()<<"  "<<shadow->top()<<endl;
      {
        // printf("sto->front()%x   shadow->top()%x  buffer%x
        // total%d\n",sto->front(),shadow->top(),buffer,total); exit(-1);
        if ((sto->empty()) ||
            (sto->front() == 0x7fffeeee || buffer == 0x7fffeeee)) {
          cout << total << "events sucess" << endl;
          cout << "No events left unprocessed.Progarm is secure" << endl;
          g_verdict = RECFA_VERDICT_SECURE;   /* RECFA-PORT */
          return true;
        }
        flag = false;
        while (!shadow->empty()) {
          // printf("shadowstack1\n");
          shadow->pop();
          // printf("shadowstack2 %d\n",shadow->size());
          if (shadow->size() > 0 && sto->front() == shadow->top()) {
            sto->pop();
            total++;
            shadow->pop();
            flag = true;
            break;
          }
        }
        if (shadow->empty() && !flag) {
          printf("fail,%ld events unprocessed\n", sto->size());
          g_verdict = RECFA_VERDICT_SHADOW;   /* RECFA-PORT */
          g_unprocessed = (long long)sto->size();
          return true;
        }
      }
    }
  }

  return false;
}

void verifiSecond(queue<int> *sto, FILE *in, int Ret, int Main) {
  int buffer = 0, last = 0;
  int rbyte = 0;
  // printf("here2\n");
  while (rbyte = fread(&buffer, 4, 1, in) == 1) {
    if (g_fatal)   /* RECFA-PORT */
      return;
    // if((buffer==0xffffeeee)&&Maintotal<executetime)
    if ((buffer < 0) && Maintotal < executetime) {
      Maintotal++;
      count1 = 0;
      // printf("%xssssssssssssssssssss",buffer);
      FtoN(sto, Main);
      fread(&buffer, 4, 1, in);
    }
    if (buffer & (2147483648)) {
      // printf("%d\n",buffer);
      buffer = buffer - 2147483648;
      sto->push(buffer);
      sto->push(recfa_direct_target(buffer));   /* RECFA-PORT */
      // printf("%xhhhhhhhhhhh\n",proMap.find(buffer)->second.directTarget);
      buffer = recfa_direct_target(buffer);   /* RECFA-PORT */
      count1 = count1 ^ 1;
    } else
      sto->push(buffer);
    if ((count1 = (count1 ^ 1)) == 0) {
      FtoN(sto, buffer);
    }
    if (sto->size() > 10000000) {
      return;
    }
  }
  // fclose(in);
  return;
}

void readTypeAmror(char *file, set<int> *IndirectSet) {
  RecfaIn f(file);   /* RECFA-PORT */
  regex Call(
      "Indirectstar0x([0-9a-z]{6})  ([0-9]{1}) Indirectend0x([0-9a-z]{6})");
  smatch m;
  string line;
  while (getline(f, line)) {
    auto ret = regex_search(line, m, Call);
    if (ret) {
      RecfaStr c = (char *)m.str(1).c_str();   /* RECFA-PORT */
      int b = strtoll(c, NULL, 16);
      if (proMap.find(b) != proMap.end()) {
        newblock &block = (proMap.find(b)->second);
        block.Type = 1;
        int d;
        c = (char *)m.str(3).c_str();
        d = strtoll(c, NULL, 16);
        block.Jump.insert(d);
        // cout<<m.str(1)<<"  "<<proMap.find(b)->second.Type<<endl;
        ret = regex_search(line, m, Call);
      } else {
        cout << "Policy F read error." << endl;
        g_fatal = RECFA_VERDICT_POLICY_F;   /* RECFA-PORT */
        return;
      }
    }
  }
}

/* ==== RECFA-PORT: C entry point used by the Wasm component shell ========= */
extern "C" int recfa_verify(const char *asm_name, const char *dot_name,
                            const char *f_name, const char *m_name,
                            const char *trace_name, int num_executions,
                            const char *compiler_type, recfa_result *out) {
  if (!out)
    return -1;

  /* Reset every upstream global so repeated calls are deterministic. */
  proMap.clear();
  ForNext.clear();
  success = 0;
  total = 0;
  timeRead = 0;
  timeTotal = 0;
  executetime = 0;
  st = 0;
  count1 = 0;
  Maintotal = 1;
  g_fatal = 0;
  g_verdict = RECFA_VERDICT_UNKNOWN;
  g_unprocessed = 0;
  g_last_site = 0;
  g_bad_target = 0;
  g_main_addr = 0;
  g_ret_addr = 0;

  char numbuf[32];
  snprintf(numbuf, sizeof(numbuf), "%d", num_executions);

  char *argv[8];
  argv[0] = const_cast<char *>("check");
  argv[1] = const_cast<char *>(asm_name);
  argv[2] = const_cast<char *>(dot_name);
  argv[3] = const_cast<char *>(f_name);
  argv[4] = const_cast<char *>(m_name);
  argv[5] = const_cast<char *>(trace_name);
  argv[6] = numbuf;
  argv[7] = const_cast<char *>(compiler_type);

  int rc = recfa_check_main(8, argv);

  memset(out, 0, sizeof(*out));
  out->verdict = g_fatal ? g_fatal : g_verdict;
  out->events_attested = (int64_t)total;
  out->events_unprocessed = (int64_t)g_unprocessed;
  out->events_reconstructed = (int64_t)success;
  out->policy_m_entries = (uint32_t)ForNext.size();
  out->policy_f_entries = (uint32_t)proMap.size();
  out->violation_site = g_last_site;
  out->violation_target = g_bad_target;
  out->main_addr = g_main_addr;
  out->main_ret_addr = g_ret_addr;
  return rc;
}
/* ======================================================================== */
