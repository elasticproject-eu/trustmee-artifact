
prog:     file format elf64-x86-64


Disassembly of section .init:

0000000000400440 <_init>:
  400440:	48 83 ec 08          	sub    $0x8,%rsp
  400444:	48 8b 05 a5 0b 20 00 	mov    0x200ba5(%rip),%rax        # 600ff0 <__gmon_start__>
  40044b:	48 85 c0             	test   %rax,%rax
  40044e:	74 02                	je     400452 <_init+0x12>
  400450:	ff d0                	callq  *%rax
  400452:	48 83 c4 08          	add    $0x8,%rsp
  400456:	c3                   	retq   

Disassembly of section .plt:

0000000000400460 <.plt>:
  400460:	ff 35 a2 0b 20 00    	pushq  0x200ba2(%rip)        # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400466:	ff 25 a4 0b 20 00    	jmpq   *0x200ba4(%rip)        # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40046c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400470 <fclose@plt>:
  400470:	ff 25 a2 0b 20 00    	jmpq   *0x200ba2(%rip)        # 601018 <fclose@GLIBC_2.2.5>
  400476:	68 00 00 00 00       	pushq  $0x0
  40047b:	e9 e0 ff ff ff       	jmpq   400460 <.plt>

0000000000400480 <fprintf@plt>:
  400480:	ff 25 9a 0b 20 00    	jmpq   *0x200b9a(%rip)        # 601020 <fprintf@GLIBC_2.2.5>
  400486:	68 01 00 00 00       	pushq  $0x1
  40048b:	e9 d0 ff ff ff       	jmpq   400460 <.plt>

0000000000400490 <fopen@plt>:
  400490:	ff 25 92 0b 20 00    	jmpq   *0x200b92(%rip)        # 601028 <fopen@GLIBC_2.2.5>
  400496:	68 02 00 00 00       	pushq  $0x2
  40049b:	e9 c0 ff ff ff       	jmpq   400460 <.plt>

Disassembly of section .text:

00000000004004a0 <_start>:
  4004a0:	31 ed                	xor    %ebp,%ebp
  4004a2:	49 89 d1             	mov    %rdx,%r9
  4004a5:	5e                   	pop    %rsi
  4004a6:	48 89 e2             	mov    %rsp,%rdx
  4004a9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4004ad:	50                   	push   %rax
  4004ae:	54                   	push   %rsp
  4004af:	49 c7 c0 a0 07 40 00 	mov    $0x4007a0,%r8
  4004b6:	48 c7 c1 30 07 40 00 	mov    $0x400730,%rcx
  4004bd:	48 c7 c7 51 06 40 00 	mov    $0x400651,%rdi
  4004c4:	ff 15 1e 0b 20 00    	callq  *0x200b1e(%rip)        # 600fe8 <__libc_start_main@GLIBC_2.2.5>
  4004ca:	f4                   	hlt    
  4004cb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004004d0 <_dl_relocate_static_pie>:
  4004d0:	f3 c3                	repz retq 
  4004d2:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4004d9:	00 00 00 
  4004dc:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004004e0 <deregister_tm_clones>:
  4004e0:	55                   	push   %rbp
  4004e1:	b8 40 10 60 00       	mov    $0x601040,%eax
  4004e6:	48 3d 40 10 60 00    	cmp    $0x601040,%rax
  4004ec:	48 89 e5             	mov    %rsp,%rbp
  4004ef:	74 17                	je     400508 <deregister_tm_clones+0x28>
  4004f1:	b8 00 00 00 00       	mov    $0x0,%eax
  4004f6:	48 85 c0             	test   %rax,%rax
  4004f9:	74 0d                	je     400508 <deregister_tm_clones+0x28>
  4004fb:	5d                   	pop    %rbp
  4004fc:	bf 40 10 60 00       	mov    $0x601040,%edi
  400501:	ff e0                	jmpq   *%rax
  400503:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400508:	5d                   	pop    %rbp
  400509:	c3                   	retq   
  40050a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400510 <register_tm_clones>:
  400510:	be 40 10 60 00       	mov    $0x601040,%esi
  400515:	55                   	push   %rbp
  400516:	48 81 ee 40 10 60 00 	sub    $0x601040,%rsi
  40051d:	48 89 e5             	mov    %rsp,%rbp
  400520:	48 c1 fe 03          	sar    $0x3,%rsi
  400524:	48 89 f0             	mov    %rsi,%rax
  400527:	48 c1 e8 3f          	shr    $0x3f,%rax
  40052b:	48 01 c6             	add    %rax,%rsi
  40052e:	48 d1 fe             	sar    %rsi
  400531:	74 15                	je     400548 <register_tm_clones+0x38>
  400533:	b8 00 00 00 00       	mov    $0x0,%eax
  400538:	48 85 c0             	test   %rax,%rax
  40053b:	74 0b                	je     400548 <register_tm_clones+0x38>
  40053d:	5d                   	pop    %rbp
  40053e:	bf 40 10 60 00       	mov    $0x601040,%edi
  400543:	ff e0                	jmpq   *%rax
  400545:	0f 1f 00             	nopl   (%rax)
  400548:	5d                   	pop    %rbp
  400549:	c3                   	retq   
  40054a:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)

0000000000400550 <__do_global_dtors_aux>:
  400550:	80 3d e9 0a 20 00 00 	cmpb   $0x0,0x200ae9(%rip)        # 601040 <__TMC_END__>
  400557:	75 17                	jne    400570 <__do_global_dtors_aux+0x20>
  400559:	55                   	push   %rbp
  40055a:	48 89 e5             	mov    %rsp,%rbp
  40055d:	e8 7e ff ff ff       	callq  4004e0 <deregister_tm_clones>
  400562:	c6 05 d7 0a 20 00 01 	movb   $0x1,0x200ad7(%rip)        # 601040 <__TMC_END__>
  400569:	5d                   	pop    %rbp
  40056a:	c3                   	retq   
  40056b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400570:	f3 c3                	repz retq 
  400572:	0f 1f 40 00          	nopl   0x0(%rax)
  400576:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40057d:	00 00 00 

0000000000400580 <frame_dummy>:
  400580:	55                   	push   %rbp
  400581:	48 89 e5             	mov    %rsp,%rbp
  400584:	5d                   	pop    %rbp
  400585:	eb 89                	jmp    400510 <register_tm_clones>

0000000000400587 <neg>:
  400587:	55                   	push   %rbp
  400588:	48 89 e5             	mov    %rsp,%rbp
  40058b:	89 7d fc             	mov    %edi,-0x4(%rbp)
  40058e:	8b 45 fc             	mov    -0x4(%rbp),%eax
  400591:	f7 d8                	neg    %eax
  400593:	5d                   	pop    %rbp
  400594:	c3                   	retq   

0000000000400595 <square>:
  400595:	55                   	push   %rbp
  400596:	48 89 e5             	mov    %rsp,%rbp
  400599:	89 7d fc             	mov    %edi,-0x4(%rbp)
  40059c:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40059f:	0f af 45 fc          	imul   -0x4(%rbp),%eax
  4005a3:	5d                   	pop    %rbp
  4005a4:	c3                   	retq   

00000000004005a5 <add>:
  4005a5:	55                   	push   %rbp
  4005a6:	48 89 e5             	mov    %rsp,%rbp
  4005a9:	89 7d fc             	mov    %edi,-0x4(%rbp)
  4005ac:	89 75 f8             	mov    %esi,-0x8(%rbp)
  4005af:	8b 55 fc             	mov    -0x4(%rbp),%edx
  4005b2:	8b 45 f8             	mov    -0x8(%rbp),%eax
  4005b5:	01 d0                	add    %edx,%eax
  4005b7:	5d                   	pop    %rbp
  4005b8:	c3                   	retq   

00000000004005b9 <mul>:
  4005b9:	55                   	push   %rbp
  4005ba:	48 89 e5             	mov    %rsp,%rbp
  4005bd:	89 7d fc             	mov    %edi,-0x4(%rbp)
  4005c0:	89 75 f8             	mov    %esi,-0x8(%rbp)
  4005c3:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005c6:	0f af 45 f8          	imul   -0x8(%rbp),%eax
  4005ca:	5d                   	pop    %rbp
  4005cb:	c3                   	retq   

00000000004005cc <fma3>:
  4005cc:	55                   	push   %rbp
  4005cd:	48 89 e5             	mov    %rsp,%rbp
  4005d0:	89 7d fc             	mov    %edi,-0x4(%rbp)
  4005d3:	89 75 f8             	mov    %esi,-0x8(%rbp)
  4005d6:	89 55 f4             	mov    %edx,-0xc(%rbp)
  4005d9:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4005dc:	0f af 45 f8          	imul   -0x8(%rbp),%eax
  4005e0:	89 c2                	mov    %eax,%edx
  4005e2:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4005e5:	01 d0                	add    %edx,%eax
  4005e7:	5d                   	pop    %rbp
  4005e8:	c3                   	retq   

00000000004005e9 <apply1>:
  4005e9:	55                   	push   %rbp
  4005ea:	48 89 e5             	mov    %rsp,%rbp
  4005ed:	48 83 ec 10          	sub    $0x10,%rsp
  4005f1:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  4005f5:	89 75 f4             	mov    %esi,-0xc(%rbp)
  4005f8:	8b 55 f4             	mov    -0xc(%rbp),%edx
  4005fb:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4005ff:	89 d7                	mov    %edx,%edi
  400601:	ff d0                	callq  *%rax
  400603:	c9                   	leaveq 
  400604:	c3                   	retq   

0000000000400605 <apply2>:
  400605:	55                   	push   %rbp
  400606:	48 89 e5             	mov    %rsp,%rbp
  400609:	48 83 ec 10          	sub    $0x10,%rsp
  40060d:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  400611:	89 75 f4             	mov    %esi,-0xc(%rbp)
  400614:	89 55 f0             	mov    %edx,-0x10(%rbp)
  400617:	8b 4d f0             	mov    -0x10(%rbp),%ecx
  40061a:	8b 55 f4             	mov    -0xc(%rbp),%edx
  40061d:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400621:	89 ce                	mov    %ecx,%esi
  400623:	89 d7                	mov    %edx,%edi
  400625:	ff d0                	callq  *%rax
  400627:	c9                   	leaveq 
  400628:	c3                   	retq   

0000000000400629 <apply3>:
  400629:	55                   	push   %rbp
  40062a:	48 89 e5             	mov    %rsp,%rbp
  40062d:	48 83 ec 20          	sub    $0x20,%rsp
  400631:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  400635:	89 75 f4             	mov    %esi,-0xc(%rbp)
  400638:	89 55 f0             	mov    %edx,-0x10(%rbp)
  40063b:	89 4d ec             	mov    %ecx,-0x14(%rbp)
  40063e:	8b 55 ec             	mov    -0x14(%rbp),%edx
  400641:	8b 75 f0             	mov    -0x10(%rbp),%esi
  400644:	8b 4d f4             	mov    -0xc(%rbp),%ecx
  400647:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40064b:	89 cf                	mov    %ecx,%edi
  40064d:	ff d0                	callq  *%rax
  40064f:	c9                   	leaveq 
  400650:	c3                   	retq   

0000000000400651 <main>:
  400651:	55                   	push   %rbp
  400652:	48 89 e5             	mov    %rsp,%rbp
  400655:	48 83 ec 10          	sub    $0x10,%rsp
  400659:	c7 45 f0 01 00 00 00 	movl   $0x1,-0x10(%rbp)
  400660:	c7 45 f4 01 00 00 00 	movl   $0x1,-0xc(%rbp)
  400667:	eb 16                	jmp    40067f <main+0x2e>
  400669:	8b 55 f4             	mov    -0xc(%rbp),%edx
  40066c:	8b 45 f0             	mov    -0x10(%rbp),%eax
  40066f:	89 d6                	mov    %edx,%esi
  400671:	89 c7                	mov    %eax,%edi
  400673:	e8 2d ff ff ff       	callq  4005a5 <add>
  400678:	89 45 f0             	mov    %eax,-0x10(%rbp)
  40067b:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
  40067f:	83 7d f4 03          	cmpl   $0x3,-0xc(%rbp)
  400683:	7e e4                	jle    400669 <main+0x18>
  400685:	48 8d 05 09 ff ff ff 	lea    -0xf7(%rip),%rax        # 400595 <square>
  40068c:	8b 55 f0             	mov    -0x10(%rbp),%edx
  40068f:	89 d6                	mov    %edx,%esi
  400691:	48 89 c7             	mov    %rax,%rdi
  400694:	e8 50 ff ff ff       	callq  4005e9 <apply1>
  400699:	89 45 f0             	mov    %eax,-0x10(%rbp)
  40069c:	48 8d 05 16 ff ff ff 	lea    -0xea(%rip),%rax        # 4005b9 <mul>
  4006a3:	8b 4d f0             	mov    -0x10(%rbp),%ecx
  4006a6:	ba 03 00 00 00       	mov    $0x3,%edx
  4006ab:	89 ce                	mov    %ecx,%esi
  4006ad:	48 89 c7             	mov    %rax,%rdi
  4006b0:	e8 50 ff ff ff       	callq  400605 <apply2>
  4006b5:	89 45 f0             	mov    %eax,-0x10(%rbp)
  4006b8:	48 8d 05 0d ff ff ff 	lea    -0xf3(%rip),%rax        # 4005cc <fma3>
  4006bf:	8b 75 f0             	mov    -0x10(%rbp),%esi
  4006c2:	b9 05 00 00 00       	mov    $0x5,%ecx
  4006c7:	ba 02 00 00 00       	mov    $0x2,%edx
  4006cc:	48 89 c7             	mov    %rax,%rdi
  4006cf:	e8 55 ff ff ff       	callq  400629 <apply3>
  4006d4:	89 45 f0             	mov    %eax,-0x10(%rbp)
  4006d7:	48 8d 35 d6 00 00 00 	lea    0xd6(%rip),%rsi        # 4007b4 <_IO_stdin_used+0x4>
  4006de:	48 8d 3d d1 00 00 00 	lea    0xd1(%rip),%rdi        # 4007b6 <_IO_stdin_used+0x6>
  4006e5:	e8 a6 fd ff ff       	callq  400490 <fopen@plt>
  4006ea:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  4006ee:	48 83 7d f8 00       	cmpq   $0x0,-0x8(%rbp)
  4006f3:	74 27                	je     40071c <main+0xcb>
  4006f5:	8b 55 f0             	mov    -0x10(%rbp),%edx
  4006f8:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4006fc:	48 8d 35 bc 00 00 00 	lea    0xbc(%rip),%rsi        # 4007bf <_IO_stdin_used+0xf>
  400703:	48 89 c7             	mov    %rax,%rdi
  400706:	b8 00 00 00 00       	mov    $0x0,%eax
  40070b:	e8 70 fd ff ff       	callq  400480 <fprintf@plt>
  400710:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  400714:	48 89 c7             	mov    %rax,%rdi
  400717:	e8 54 fd ff ff       	callq  400470 <fclose@plt>
  40071c:	b8 00 00 00 00       	mov    $0x0,%eax
  400721:	c9                   	leaveq 
  400722:	c3                   	retq   
  400723:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40072a:	00 00 00 
  40072d:	0f 1f 00             	nopl   (%rax)

0000000000400730 <__libc_csu_init>:
  400730:	41 57                	push   %r15
  400732:	41 56                	push   %r14
  400734:	49 89 d7             	mov    %rdx,%r15
  400737:	41 55                	push   %r13
  400739:	41 54                	push   %r12
  40073b:	4c 8d 25 9e 06 20 00 	lea    0x20069e(%rip),%r12        # 600de0 <__frame_dummy_init_array_entry>
  400742:	55                   	push   %rbp
  400743:	48 8d 2d 9e 06 20 00 	lea    0x20069e(%rip),%rbp        # 600de8 <__init_array_end>
  40074a:	53                   	push   %rbx
  40074b:	41 89 fd             	mov    %edi,%r13d
  40074e:	49 89 f6             	mov    %rsi,%r14
  400751:	4c 29 e5             	sub    %r12,%rbp
  400754:	48 83 ec 08          	sub    $0x8,%rsp
  400758:	48 c1 fd 03          	sar    $0x3,%rbp
  40075c:	e8 df fc ff ff       	callq  400440 <_init>
  400761:	48 85 ed             	test   %rbp,%rbp
  400764:	74 20                	je     400786 <__libc_csu_init+0x56>
  400766:	31 db                	xor    %ebx,%ebx
  400768:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40076f:	00 
  400770:	4c 89 fa             	mov    %r15,%rdx
  400773:	4c 89 f6             	mov    %r14,%rsi
  400776:	44 89 ef             	mov    %r13d,%edi
  400779:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40077d:	48 83 c3 01          	add    $0x1,%rbx
  400781:	48 39 dd             	cmp    %rbx,%rbp
  400784:	75 ea                	jne    400770 <__libc_csu_init+0x40>
  400786:	48 83 c4 08          	add    $0x8,%rsp
  40078a:	5b                   	pop    %rbx
  40078b:	5d                   	pop    %rbp
  40078c:	41 5c                	pop    %r12
  40078e:	41 5d                	pop    %r13
  400790:	41 5e                	pop    %r14
  400792:	41 5f                	pop    %r15
  400794:	c3                   	retq   
  400795:	90                   	nop
  400796:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40079d:	00 00 00 

00000000004007a0 <__libc_csu_fini>:
  4007a0:	f3 c3                	repz retq 

Disassembly of section .fini:

00000000004007a4 <_fini>:
  4007a4:	48 83 ec 08          	sub    $0x8,%rsp
  4007a8:	48 83 c4 08          	add    $0x8,%rsp
  4007ac:	c3                   	retq   
