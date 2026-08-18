
prog:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <main>:
  401000:	55                   	push   %rbp
  401010:	e8 eb 00 00 00       	callq  401100 <foo>
  401015:	48 89 e5             	mov    %rsp,%rbp
  401020:	ff d0                	callq  *%rax
  401025:	48 89 e5             	mov    %rsp,%rbp
  401030:	ff e0                	jmpq   *%rax
  401040:	48 89 e5             	mov    %rsp,%rbp
  401050:	c3                   	retq   

0000000000401100 <foo>:
  401100:	55                   	push   %rbp
  401110:	c3                   	retq   

0000000000401200 <bar>:
  401200:	55                   	push   %rbp
  401210:	c3                   	retq   

